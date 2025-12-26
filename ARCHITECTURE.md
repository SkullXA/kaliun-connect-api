# Kaliun Connect API - Architecture & Issues

## Current State Analysis

### ❌ **CRITICAL: No User Role System**

**Current Implementation:**
- All users are treated equally
- No distinction between Home Owners, Installers, or Admins
- No role-based access control (RBAC)
- No permission system
- Anyone who can claim a device has full access to it

**Database Schema:**
```sql
-- users table has NO role field
CREATE TABLE public.users (
  id UUID PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT,
  name TEXT,
  provider TEXT DEFAULT 'email',
  -- ❌ MISSING: role TEXT, permissions JSONB, etc.
);
```

**Code Evidence:**
- `requireAuth` middleware only checks if user is logged in
- No `requireRole()` or `requirePermission()` middleware
- Installation ownership is binary: `claimed_by` UUID only
- No installer assignment, no admin override

---

## Proposed User Role Architecture

### 1. **User Roles**

#### **Home Owner** (default role)
- **Purpose**: End user who owns the KaliunBox
- **Created**: When user claims a device
- **Access**:
  - ✅ View their own installations
  - ✅ View logs for their installations
  - ✅ View health status for their installations
  - ✅ Update customer info (name, email, address)
  - ❌ Cannot claim devices for others
  - ❌ Cannot view other users' installations
  - ❌ Cannot manage installers
  - ❌ Cannot access admin features

**UI Menus:**
- Dashboard (My Installations)
- Installation Details (their own)
- Settings (Profile only)
- Logout

---

#### **Installer** (professional role)
- **Purpose**: Professional installer who sets up KaliunBoxes for customers
- **Created**: By Admin via invite or manual creation
- **Access**:
  - ✅ Claim devices on behalf of customers
  - ✅ View all installations they've claimed/assigned to
  - ✅ View logs for assigned installations
  - ✅ Update customer info for assigned installations
  - ✅ Assign installations to Home Owners
  - ✅ Transfer ownership to Home Owners
  - ✅ View installer dashboard (all their installations)
  - ❌ Cannot access admin features
  - ❌ Cannot view other installers' installations (unless shared)

**UI Menus:**
- Dashboard (All My Installations)
- Installation Details (assigned installations)
- Customer Management
- Installer Settings
- Logout

**Database Changes Needed:**
```sql
-- Add installer_id to installations
ALTER TABLE installations ADD COLUMN installer_id UUID REFERENCES users(id);

-- Track installer assignments
CREATE TABLE installer_assignments (
  id UUID PRIMARY KEY,
  installer_id UUID REFERENCES users(id),
  installation_id UUID REFERENCES installations(id),
  assigned_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(installer_id, installation_id)
);
```

---

#### **Admin** (system administrator)
- **Purpose**: Kaliun staff managing the platform
- **Created**: Manually in database or via special invite
- **Access**:
  - ✅ **Full system access**
  - ✅ View ALL installations (all users)
  - ✅ View ALL logs (all installations)
  - ✅ Manage users (create, delete, change roles)
  - ✅ Manage installers (assign, revoke)
  - ✅ System settings
  - ✅ Analytics and reporting
  - ✅ Debug tools
  - ✅ Override any installation ownership
  - ✅ Access health reports for all devices

**UI Menus:**
- Admin Dashboard (System Overview)
- All Installations (with filters)
- User Management
- Installer Management
- System Settings
- Analytics
- Debug Tools
- Logout

**Database Changes Needed:**
```sql
-- Add role to users
ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'home_owner';
ALTER TABLE users ADD CONSTRAINT valid_role CHECK (role IN ('home_owner', 'installer', 'admin'));

-- Add admin-specific permissions
ALTER TABLE users ADD COLUMN permissions JSONB DEFAULT '{}';
```

---

### 2. **Access Control Matrix**

| Action | Home Owner | Installer | Admin |
|--------|-----------|-----------|-------|
| View own installations | ✅ | ✅ | ✅ |
| View assigned installations | ❌ | ✅ | ✅ |
| View ALL installations | ❌ | ❌ | ✅ |
| Claim device | ✅ (own) | ✅ (any) | ✅ |
| View own logs | ✅ | ✅ | ✅ |
| View assigned logs | ❌ | ✅ | ✅ |
| View ALL logs | ❌ | ❌ | ✅ |
| Update customer info (own) | ✅ | ✅ | ✅ |
| Update customer info (assigned) | ❌ | ✅ | ✅ |
| Update customer info (any) | ❌ | ❌ | ✅ |
| Assign installer | ❌ | ❌ | ✅ |
| Transfer ownership | ❌ | ✅ | ✅ |
| Manage users | ❌ | ❌ | ✅ |
| System settings | ❌ | ❌ | ✅ |

---

### 3. **API Endpoint Protection**

**Current (BROKEN):**
```javascript
app.get('/installations', requireAuth, async (req, res) => {
  // ❌ No role check - anyone can see their installations
  const installations = await db.findInstallationsByUserId(userId);
});
```

**Proposed:**
```javascript
// Middleware for role checking
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).redirect('/login');
    if (!roles.includes(req.user.role)) {
      return res.status(403).send('Forbidden: Insufficient permissions');
    }
    next();
  };
}

// Protected routes
app.get('/installations', requireAuth, async (req, res) => {
  let installations;
  if (req.user.role === 'admin') {
    installations = await db.findAllInstallations(); // All
  } else if (req.user.role === 'installer') {
    installations = await db.findInstallationsByInstallerId(req.user.id);
  } else {
    installations = await db.findInstallationsByUserId(req.user.id); // Own only
  }
  // ...
});

app.get('/admin/users', requireAuth, requireRole('admin'), async (req, res) => {
  // Admin-only endpoint
});
```

---

## 🐛 **BUGS IDENTIFIED**

### **Bug #1: Log Reporting Issues**

#### **Problem 1.1: Logs Not Sending Data**
**Location:** `kaliunbox-nix/modules/log-reporter.nix`

**Issue:**
```bash
# Line 83-89: Early exit if no logs
if [ -z "$ALL_LOGS" ]; then
  echo "No new logs to send"
  if [ -n "$NEW_CURSOR" ]; then
    echo "$NEW_CURSOR" > "$LAST_SENT_FILE"
  fi
  exit 0  # ❌ Exits silently, no error indication
fi
```

**Root Causes:**
1. **Cursor tracking may be broken**: If cursor file gets corrupted or reset, logs may be skipped
2. **Service names may not match**: Log reporter looks for specific service names, but systemd unit names might differ
3. **Journalctl may return empty**: If services haven't logged anything, `journalctl` returns empty string
4. **No retry mechanism**: If API call fails, logs are lost (no retry queue)

**Evidence:**
- Log reporter runs every 15 minutes (`OnUnitActiveSec = "15min"`)
- If no logs found, it exits early without sending anything
- Cursor is updated even when no logs sent, potentially skipping logs

**Fix Needed:**
- Add logging when no logs found (debug why)
- Verify service names match actual systemd units
- Add retry queue for failed sends
- Add health check to verify log collection is working

---

#### **Problem 1.2: Home Assistant Logs Rarely Sent**
**Location:** `kaliunbox-nix/modules/log-reporter.nix:31-42`

**Issue:**
```bash
SERVICES=(
  "homeassistant-vm.service"
  "homeassistant-info-fetcher.service"
  "homeassistant-proxy-setup.service"
  "homeassistant-health-check.service"
  "homeassistant-watchdog.service"
  # ...
)
```

**Root Causes:**
1. **Service may not exist**: If `homeassistant-vm.service` isn't running or doesn't exist, `journalctl -u` returns empty
2. **Logs may be in different location**: HA logs might be inside the VM, not in host journald
3. **Service name mismatch**: Actual service name might be different
4. **No fallback mechanism**: If service doesn't exist, no attempt to get logs from VM

**Evidence:**
- HA runs in a QEMU VM, logs are likely inside the VM
- Host systemd only sees VM lifecycle logs, not HA application logs
- No mechanism to extract logs from inside the VM

**Fix Needed:**
- Verify actual systemd service names exist
- Add mechanism to extract logs from inside HA VM (via QEMU guest agent or SSH)
- Add fallback to read HA logs from VM filesystem
- Log which services are found vs not found

---

#### **Problem 1.3: System Logs Not Categorized Correctly**
**Location:** `kaliunbox-nix/modules/log-reporter.nix:105`

**Issue:**
```bash
service: (._SYSTEMD_UNIT // .SYSLOG_IDENTIFIER // "system"),
```

**Root Causes:**
1. **Fallback to "system"**: Many logs end up as "system" instead of actual service name
2. **SYSLOG_IDENTIFIER may be missing**: Some logs don't have this field
3. **No service name normalization**: Different formats (e.g., "homeassistant-vm" vs "homeassistant-vm.service")

**Evidence:**
- API receives many logs with `service: "system"`
- Makes filtering difficult in UI
- Can't properly categorize logs by service

**Fix Needed:**
- Better service name extraction
- Normalize service names (remove `.service` suffix)
- Map common log sources to service names
- Add service name validation

---

### **Bug #2: Status Detection Issues**

#### **Problem 2.1: Shows Offline When Online**
**Location:** `kaliun-connect-api/src/index.js:948, 987`

**Issue:**
```javascript
const isOnline = i.last_health_at && 
  (Date.now() - new Date(i.last_health_at).getTime()) < 10 * 60 * 1000;
```

**Root Causes:**
1. **10-minute timeout may be too short**: If health reporter fails once, device shows offline
2. **Health reporter may not be running**: Timer may not be firing
3. **Network issues**: Device may be online but can't reach API
4. **Time zone issues**: `last_health_at` is stored as TIMESTAMPTZ, but comparison might be wrong
5. **Health endpoint may be failing silently**: If health POST fails, `last_health_at` isn't updated

**Evidence:**
- Status check: `(Date.now() - new Date(i.last_health_at).getTime()) < 10 * 60 * 1000`
- If health hasn't been reported in 10 minutes, shows offline
- No distinction between "never reported" and "stale report"

**Fix Needed:**
- Increase timeout to 15-20 minutes (health reports every 15min)
- Add "unknown" status for devices that have never reported
- Add last seen timestamp display
- Verify health reporter timer is running
- Add health report failure logging

---

#### **Problem 2.2: Health Reporter May Not Be Running**
**Location:** `kaliunbox-nix/modules/health-reporter.nix`

**Issue:**
- Health reporter runs on timer: `OnBootSec = "2min"`, `OnUnitActiveSec = "15min"`
- If timer fails or service crashes, no health reports sent
- No alerting when health reports stop

**Root Causes:**
1. **Timer may not be active**: Systemd timer might not be enabled
2. **Service may be failing**: Health script might be erroring out
3. **Network connectivity**: Device may be online but can't reach API
4. **Token expiration**: Bearer token may have expired, causing 401 errors

**Evidence:**
- Health endpoint requires Bearer auth
- If token expires, health reports fail silently
- No retry mechanism for failed health reports

**Fix Needed:**
- Verify timer is active: `systemctl status kaliun-health-reporter.timer`
- Add health report retry mechanism
- Log health report failures
- Add token refresh before health report
- Add alerting when health reports stop

---

#### **Problem 2.3: Status Calculation Logic**
**Location:** `kaliun-connect-api/src/index.js:987`

**Issue:**
```javascript
const isOnline = installation.last_health_at && 
  (Date.now() - new Date(installation.last_health_at).getTime()) < 10 * 60 * 1000;
```

**Problems:**
1. **No null check for Date parsing**: If `last_health_at` is invalid, `new Date()` returns invalid date
2. **No timezone handling**: Server time vs device time may differ
3. **Hardcoded 10 minutes**: Should be configurable
4. **No status history**: Can't see when device went offline

**Fix Needed:**
- Add proper date validation
- Use consistent timezone (UTC)
- Make timeout configurable
- Add status history tracking
- Add "last seen" display

---

## Database Schema Changes Needed

### 1. **Add User Roles**
```sql
-- Add role column
ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'home_owner';
ALTER TABLE users ADD CONSTRAINT valid_role 
  CHECK (role IN ('home_owner', 'installer', 'admin'));

-- Add permissions (for future flexibility)
ALTER TABLE users ADD COLUMN permissions JSONB DEFAULT '{}';

-- Create index for role queries
CREATE INDEX idx_users_role ON users(role);
```

### 2. **Add Installer Assignments**
```sql
-- Track which installer is assigned to which installation
ALTER TABLE installations ADD COLUMN installer_id UUID REFERENCES users(id);

-- Create installer assignments table (many-to-many)
CREATE TABLE installer_assignments (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  installer_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  installation_id UUID NOT NULL REFERENCES installations(id) ON DELETE CASCADE,
  assigned_at TIMESTAMPTZ DEFAULT NOW(),
  assigned_by UUID REFERENCES users(id),
  UNIQUE(installer_id, installation_id)
);

CREATE INDEX idx_installer_assignments_installer ON installer_assignments(installer_id);
CREATE INDEX idx_installer_assignments_installation ON installer_assignments(installation_id);
```

### 3. **Add Status History**
```sql
-- Track status changes over time
CREATE TABLE installation_status_history (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  installation_id UUID NOT NULL REFERENCES installations(id) ON DELETE CASCADE,
  status TEXT NOT NULL, -- 'online', 'offline', 'unknown'
  last_health_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_status_history_installation ON installation_status_history(installation_id);
CREATE INDEX idx_status_history_created ON installation_status_history(created_at DESC);
```

### 4. **Add Log Metadata**
```sql
-- Add fields to help debug log issues
ALTER TABLE logs ADD COLUMN source TEXT; -- 'systemd', 'vm', 'application'
ALTER TABLE logs ADD COLUMN collected_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE logs ADD COLUMN cursor TEXT; -- Track journalctl cursor

CREATE INDEX idx_logs_source ON logs(source);
CREATE INDEX idx_logs_collected ON logs(collected_at DESC);
```

---

## API Endpoint Changes Needed

### 1. **Add Role-Based Endpoints**

```javascript
// Admin endpoints
GET  /api/v1/admin/users              // List all users
POST /api/v1/admin/users              // Create user
PUT  /api/v1/admin/users/:id          // Update user role
GET  /api/v1/admin/installations      // List all installations
GET  /api/v1/admin/analytics          // System analytics

// Installer endpoints
GET  /api/v1/installer/installations  // Installer's assigned installations
POST /api/v1/installer/assign         // Assign installation to installer
POST /api/v1/installer/transfer       // Transfer ownership to home owner

// Home Owner endpoints (existing, but need protection)
GET  /api/v1/installations            // Only own installations
GET  /api/v1/installations/:id        // Only if owner
```

### 2. **Add Logging Endpoints**

```javascript
// Debug log collection
GET  /api/v1/installations/:id/logs/debug    // Get log collection status
POST /api/v1/installations/:id/logs/trigger // Manually trigger log collection

// Log statistics
GET  /api/v1/installations/:id/logs/stats    // Log collection statistics
```

### 3. **Add Status Endpoints**

```javascript
// Status history
GET  /api/v1/installations/:id/status/history // Status change history

// Status debug
GET  /api/v1/installations/:id/status/debug   // Why is status X?
```

---

## UI Changes Needed

### **Current UI Stack**
- ❌ **Pure CSS** (no framework - Tailwind, Bootstrap, etc.)
- ❌ **Inline styles** embedded in Express server
- ❌ **Basic custom classes** - looks unprofessional
- ❌ **No component system** - everything is string templates

### **Recommended UI Stack**
**Option 1: Modern CSS Framework (Recommended)**
- Use **Tailwind CSS** via CDN or build process
- Professional, consistent design system
- Responsive by default
- Easy to maintain

**Option 2: Component Library**
- **shadcn/ui** (React) or **Headless UI** (vanilla JS)
- Pre-built professional components
- Accessible and modern

**Option 3: CSS Framework**
- **Bootstrap 5** or **Bulma** - easier migration path
- Less modern but battle-tested

---

### 1. **Professional Badge/Pill Styling**

**Current (Looney Tunes Style):**
```css
.status { 
  padding: 4px 12px; 
  border-radius: 20px; 
  font-size: 12px; 
}
.status::before { 
  content: ''; 
  width: 8px; 
  height: 8px; 
  border-radius: 50%; 
}
```

**Professional Style (Like Screenshot):**
```css
.badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  border-radius: 9999px; /* Fully rounded */
  font-size: 12px;
  font-weight: 500;
  letter-spacing: 0.025em;
  text-transform: none; /* Don't uppercase */
  border: 1px solid transparent;
  transition: all 0.2s;
}

.badge-success {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
  border-color: rgba(34, 197, 94, 0.2);
}

.badge-error {
  background: rgba(239, 68, 68, 0.1);
  color: #ef4444;
  border-color: rgba(239, 68, 68, 0.2);
}

.badge-warning {
  background: rgba(234, 179, 8, 0.1);
  color: #eab308;
  border-color: rgba(234, 179, 8, 0.2);
}

.badge-info {
  background: rgba(59, 130, 246, 0.1);
  color: #3b82f6;
  border-color: rgba(59, 130, 246, 0.2);
}

/* Status dot (smaller, more subtle) */
.badge::before {
  content: '';
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
  opacity: 0.8;
}
```

---

### 2. **Enhanced Dashboard Layout**

**Current:** Basic two-column grid
**Professional:** Multi-section card layout with proper spacing

**Key Improvements:**
- **Better card spacing**: `gap: 24px` between cards
- **Card headers**: Clear section titles with icons
- **Metric cards**: Large numbers with labels and subtext
- **Progress bars**: With percentage and actual values
- **Service cards**: Icon + status + details in clean layout
- **Timeline component**: Vertical timeline with icons and timestamps

---

### 3. **Missing Features from Screenshot**

#### **3.1 Subscription/Plan Management** ⭐ NEW
**Current:** ❌ Not implemented
**Screenshot Shows:**
- Subscription status badge ("pending", "active", "cancelled")
- Plan name ("Essential $39/mo")
- Usage metrics with progress bars:
  - Devices: "6 / 50"
  - Integrations: "2 / 15"
- Stripe customer link

**Implementation Needed:**
```sql
-- Add subscription table
CREATE TABLE subscriptions (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  plan_name TEXT, -- 'essential', 'pro', 'enterprise'
  status TEXT, -- 'pending', 'active', 'cancelled', 'past_due'
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  current_period_start TIMESTAMPTZ,
  current_period_end TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Add usage tracking
CREATE TABLE subscription_usage (
  id UUID PRIMARY KEY,
  subscription_id UUID REFERENCES subscriptions(id),
  metric_name TEXT, -- 'devices', 'integrations', 'storage_gb'
  current_usage INTEGER,
  limit_value INTEGER,
  period_start TIMESTAMPTZ,
  period_end TIMESTAMPTZ
);
```

**API Endpoints:**
```javascript
GET  /api/v1/subscription              // Get user's subscription
GET  /api/v1/subscription/usage         // Get usage metrics
POST /api/v1/subscription/upgrade       // Upgrade plan
POST /api/v1/subscription/cancel        // Cancel subscription
```

---

#### **3.2 Incident Tracking** ⭐ NEW
**Current:** ❌ Not implemented
**Screenshot Shows:**
- Timeline entry: "Incident Resolved"
- Tags: "Rebuild Failed" (red), "Failed Units" (orange)
- Timestamps: Created and Resolved
- External link to incident details

**Implementation Needed:**
```sql
CREATE TABLE incidents (
  id UUID PRIMARY KEY,
  installation_id UUID REFERENCES installations(id),
  title TEXT NOT NULL,
  description TEXT,
  severity TEXT, -- 'low', 'medium', 'high', 'critical'
  status TEXT, -- 'open', 'investigating', 'resolved', 'closed'
  tags TEXT[], -- Array of tags
  created_at TIMESTAMPTZ DEFAULT NOW(),
  resolved_at TIMESTAMPTZ,
  resolved_by UUID REFERENCES users(id)
);

CREATE TABLE incident_tags (
  id UUID PRIMARY KEY,
  incident_id UUID REFERENCES incidents(id),
  tag TEXT NOT NULL,
  color TEXT -- 'red', 'orange', 'blue', etc.
);
```

**API Endpoints:**
```javascript
GET  /api/v1/installations/:id/incidents
POST /api/v1/installations/:id/incidents
PUT  /api/v1/incidents/:id/resolve
GET  /api/v1/incidents/:id
```

---

#### **3.3 Enhanced Timeline Component** ⭐ IMPROVE
**Current:** Basic timeline with dots
**Screenshot Shows:**
- Icons for each event type (plus, chain link, gear, download, checkmark)
- Clear timestamps
- Event descriptions
- Clickable items

**Improvements:**
```css
.timeline {
  position: relative;
  padding-left: 32px;
}

.timeline-item {
  position: relative;
  padding-bottom: 24px;
  padding-left: 40px;
}

.timeline-item::before {
  content: '';
  position: absolute;
  left: 8px;
  top: 0;
  bottom: -24px;
  width: 2px;
  background: linear-gradient(to bottom, #333, transparent);
}

.timeline-icon {
  position: absolute;
  left: 0;
  width: 24px;
  height: 24px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #1a1a1a;
  border: 2px solid #333;
  z-index: 1;
}

.timeline-icon.success {
  background: rgba(34, 197, 94, 0.1);
  border-color: #22c55e;
  color: #22c55e;
}

.timeline-content {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.timeline-title {
  font-weight: 500;
  color: #fff;
}

.timeline-time {
  font-size: 12px;
  color: #666;
}

.timeline-tags {
  display: flex;
  gap: 6px;
  margin-top: 8px;
}
```

---

#### **3.4 Better Service Cards** ⭐ IMPROVE
**Current:** Basic service card
**Screenshot Shows:**
- Icon with colored background
- Service name + description
- Status badge (professional style)
- Additional details (VM IP, Version, OS Version)
- Connection status with info icon

**Improvements:**
```html
<div class="service-card">
  <div class="service-icon ha">
    <svg>...</svg>
  </div>
  <div class="service-content">
    <div class="service-header">
      <h4>Home Assistant</h4>
      <span class="badge badge-success">Running</span>
    </div>
    <p class="service-description">Smart home platform</p>
    <div class="service-details">
      <div class="detail-item">
        <span class="detail-label">VM IP:</span>
        <span class="detail-value">192.168.86.123</span>
      </div>
      <div class="detail-item">
        <span class="detail-label">Version:</span>
        <span class="detail-value">2025.12.4</span>
      </div>
      <div class="detail-item">
        <span class="detail-label">OS Version:</span>
        <span class="detail-value">16.3</span>
      </div>
    </div>
  </div>
</div>
```

---

#### **3.5 Progress Bars with Labels** ⭐ IMPROVE
**Current:** Basic progress bar
**Screenshot Shows:**
- Label + percentage on same line
- Actual values below (e.g., "4.8 GiB used / 15.4 GiB total")
- Color-coded (green/yellow/red based on usage)
- Smooth gradients

**Improvements:**
```css
.metric-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.metric-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 13px;
}

.metric-label {
  color: #999;
}

.metric-percent {
  font-weight: 600;
  color: #fff;
}

.progress-container {
  height: 8px;
  background: #1a1a1a;
  border-radius: 4px;
  overflow: hidden;
  position: relative;
}

.progress-bar {
  height: 100%;
  border-radius: 4px;
  transition: width 0.3s ease;
  background: linear-gradient(90deg, var(--color-start), var(--color-end));
}

.metric-values {
  display: flex;
  justify-content: space-between;
  font-size: 11px;
  color: #666;
  margin-top: 4px;
}
```

---

#### **3.6 Remote Access Status** ⭐ NEW
**Current:** ❌ Not shown
**Screenshot Shows:**
- "Remote Access" section
- Status: "Not configured" with globe icon
- Should show connection status when configured

**Implementation:**
- Check if Pangolin/Newt is configured
- Show connection status
- Add "Configure" button if not set up

---

#### **3.7 Installer Information** ⭐ NEW
**Current:** ❌ Not shown
**Screenshot Shows:**
- "Installer" section with name and email
- Clickable (arrow icon) to view installer details

**Implementation:**
- Show installer who claimed/assigned the installation
- Link to installer profile (if user has permission)
- Only visible if installer is assigned

---

#### **3.8 Better Typography & Spacing** ⭐ IMPROVE
**Current:** Basic font sizes
**Screenshot Shows:**
- Clear hierarchy: H1 > H2 > H3 > Body > Small
- Proper line heights
- Consistent spacing (8px grid system)
- Better color contrast

**Improvements:**
```css
/* Typography Scale */
h1 { font-size: 28px; font-weight: 700; line-height: 1.2; }
h2 { font-size: 20px; font-weight: 600; line-height: 1.3; }
h3 { font-size: 14px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
body { font-size: 14px; line-height: 1.5; }
small { font-size: 12px; line-height: 1.4; }

/* Spacing System (8px grid) */
.gap-1 { gap: 4px; }
.gap-2 { gap: 8px; }
.gap-3 { gap: 12px; }
.gap-4 { gap: 16px; }
.gap-6 { gap: 24px; }
.gap-8 { gap: 32px; }
```

---

### 4. **Role-Based Navigation**

**Home Owner:**
```
Nav: [Kaliun] [My Installations] [Settings] [Logout]
```

**Installer:**
```
Nav: [Kaliun] [Dashboard] [Installations] [Customers] [Settings] [Logout]
```

**Admin:**
```
Nav: [Kaliun] [Dashboard] [All Installations] [Users] [Installers] [Analytics] [Settings] [Logout]
```

---

### 5. **Installation List Filters**

**Home Owner:**
- No filters (only sees own)

**Installer:**
- Filter by: Status, Customer, Date Claimed
- Search by: Customer name, Install ID

**Admin:**
- Filter by: Status, Owner, Installer, Date, Architecture
- Search by: Any field
- Bulk actions: Assign installer, Transfer ownership

---

### 6. **Status Display Improvements**

- Show "Last Seen: 2 minutes ago" instead of just Online/Offline ✅ (Screenshot shows this)
- Add status history timeline ✅ (Screenshot shows timeline)
- Show health report frequency
- Add "Refresh Status" button
- Show connection quality indicator

---

### 7. **Log Display Improvements**

- Show log collection status ("Last collected: 5 min ago")
- Show which services are being monitored
- Add "Collect Logs Now" button
- Show log collection errors
- Filter by service, level, time range
- Export logs

---

## Implementation Phases - Step-by-Step Guide

### **PHASE 1: Critical Fixes & Foundation** (Week 1)
**Goal:** Fix bugs and establish foundation for future features

#### **Step 1.1: Fix Log Reporting Bugs**
**Files to modify:**
- `kaliunbox-nix/modules/log-reporter.nix`

**Changes:**
1. Add debug logging when no logs found
2. Verify service names match actual systemd units
3. Add retry queue for failed log sends
4. Fix cursor tracking issues
5. Add health check to verify log collection

**Testing:**
- Verify logs appear in API within 15 minutes
- Check that HA service logs are collected
- Verify cursor doesn't skip logs

---

#### **Step 1.2: Fix Status Detection**
**Files to modify:**
- `kaliun-connect-api/src/index.js` (status calculation)
- `kaliunbox-nix/modules/health-reporter.nix` (health reporting)

**Changes:**
1. Increase timeout from 10 to 15 minutes
2. Add null checks for date parsing
3. Add "unknown" status for never-reported devices
4. Add timezone handling (use UTC consistently)
5. Add health report retry mechanism
6. Add token refresh before health report

**Testing:**
- Verify online status shows correctly
- Verify offline after 15+ minutes of no reports
- Verify "unknown" for new devices

---

#### **Step 1.3: Add Role System to Database**
**Files to modify:**
- `kaliun-connect-api/src/migrations/001_initial_schema.sql` (or create new migration)

**SQL Migration:**
```sql
-- Add role column
ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'home_owner';
ALTER TABLE users ADD CONSTRAINT valid_role 
  CHECK (role IN ('home_owner', 'installer', 'admin'));

-- Add permissions (for future flexibility)
ALTER TABLE users ADD COLUMN permissions JSONB DEFAULT '{}';

-- Create index
CREATE INDEX idx_users_role ON users(role);

-- Set existing users to home_owner (if any)
UPDATE users SET role = 'home_owner' WHERE role IS NULL;
```

**Testing:**
- Verify migration runs without errors
- Verify existing users have 'home_owner' role
- Verify constraint prevents invalid roles

---

#### **Step 1.4: Add Basic Role Middleware**
**Files to modify:**
- `kaliun-connect-api/src/index.js`

**Changes:**
1. Add `requireRole()` middleware function
2. Add role to `req.user` object in `requireAuth`
3. Add helper function to check permissions

**Code:**
```javascript
// Add after requireAuth middleware
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).redirect('/login');
    }
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).send('Forbidden: Insufficient permissions');
    }
    next();
  };
}
```

**Testing:**
- Verify middleware blocks unauthorized access
- Verify admin can access admin routes
- Verify home_owner cannot access admin routes

---

### **PHASE 2: Access Control & Role System** (Week 2)
**Goal:** Implement full role-based access control

#### **Step 2.1: Installer Assignment System**
**Files to modify:**
- `kaliun-connect-api/src/migrations/` (new migration)
- `kaliun-connect-api/src/db.js`
- `kaliun-connect-api/src/index.js`

**Database:**
```sql
-- Add installer_id to installations
ALTER TABLE installations ADD COLUMN installer_id UUID REFERENCES users(id);

-- Create installer assignments table
CREATE TABLE installer_assignments (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  installer_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  installation_id UUID NOT NULL REFERENCES installations(id) ON DELETE CASCADE,
  assigned_at TIMESTAMPTZ DEFAULT NOW(),
  assigned_by UUID REFERENCES users(id),
  UNIQUE(installer_id, installation_id)
);

CREATE INDEX idx_installer_assignments_installer ON installer_assignments(installer_id);
CREATE INDEX idx_installer_assignments_installation ON installer_assignments(installation_id);
```

**API Endpoints:**
```javascript
// Admin/Installer: Assign installer to installation
POST /api/v1/installations/:id/assign-installer
Body: { installer_id: "uuid" }

// Installer: View assigned installations
GET /api/v1/installer/installations

// Installer: Transfer ownership to home owner
POST /api/v1/installations/:id/transfer-ownership
Body: { home_owner_id: "uuid" }
```

**Testing:**
- Verify installer can see assigned installations
- Verify installer cannot see unassigned installations
- Verify transfer ownership works

---

#### **Step 2.2: Role-Based API Protection**
**Files to modify:**
- `kaliun-connect-api/src/index.js` (all routes)

**Changes:**
1. Update `/installations` route to filter by role
2. Add admin-only routes
3. Add installer routes
4. Protect installation detail routes by ownership/assignment

**Code Pattern:**
```javascript
app.get('/installations', requireAuth, async (req, res) => {
  let installations;
  if (req.user.role === 'admin') {
    installations = await db.findAllInstallations();
  } else if (req.user.role === 'installer') {
    installations = await db.findInstallationsByInstallerId(req.user.id);
  } else {
    installations = await db.findInstallationsByUserId(req.user.id);
  }
  // ... render
});
```

**Testing:**
- Verify home owners only see own installations
- Verify installers see assigned installations
- Verify admins see all installations

---

#### **Step 2.3: Update UI for Role-Based Navigation**
**Files to modify:**
- `kaliun-connect-api/src/index.js` (HTML templates)

**Changes:**
1. Add role-based navigation menu
2. Hide/show menu items based on role
3. Add admin dashboard route
4. Add installer dashboard route

**Testing:**
- Verify correct menu shows for each role
- Verify admin can access admin pages
- Verify installer can access installer pages

---

### **PHASE 3: Enhanced Statistics & Home Assistant Data** (Week 3)
**Goal:** Display comprehensive hardware and HA statistics

#### **Step 3.1: Enhanced Hardware Statistics**
**Files to modify:**
- `kaliunbox-nix/modules/health-reporter.nix` (collect more data)
- `kaliun-connect-api/src/index.js` (display hardware info)

**Additional Data to Collect:**
```javascript
// Add to health report payload
{
  hardware: {
    cpu: {
      model: "Intel Core i5-1235U",
      cores: 8,
      threads: 12,
      frequency_mhz: 2400
    },
    memory: {
      total_bytes: 16492674416,
      available_bytes: 11345678912,
      used_bytes: 5146995504,
      swap_total_bytes: 0,
      swap_used_bytes: 0
    },
    storage: {
      root: {
        total_bytes: 502384517120,
        used_bytes: 10952192000,
        available_bytes: 491432325120,
        filesystem: "ext4"
      },
      ha_vm: {
        total_bytes: 34359738368,
        used_bytes: 6012954214,
        available_bytes: 28346784154
      }
    },
    network: {
      interfaces: [
        {
          name: "eth0",
          type: "ethernet",
          speed_mbps: 1000,
          mac_address: "00:11:22:33:44:55",
          ip_addresses: ["192.168.1.100"]
        }
      ]
    }
  }
}
```

**UI Display:**
- CPU information card
- Memory breakdown (used/available/cached)
- Storage breakdown (root + HA VM)
- Network interfaces list
- System load averages (already collected)

**Testing:**
- Verify all hardware data is collected
- Verify data displays correctly in UI
- Verify data updates on each health report

---

#### **Step 3.2: Home Assistant Statistics Display**
**Files to modify:**
- `kaliunbox-nix/modules/health-reporter.nix` (already collects some HA data)
- `kaliun-connect-api/src/index.js` (display HA stats)

**Current Data Collected (from health-reporter.nix):**
```javascript
// Already in health report
home_assistant: {
  status: "running",
  ip_address: "192.168.86.123",
  version: "2025.12.4",
  os_version: "16.3",
  device_count: 42,        // ✅ Already collected
  integration_count: 15,   // ✅ Already collected
  watchdog_failures: 0,
  watchdog_last_restart: "2024-12-22T10:30:00Z"
}
```

**Additional Data to Collect:**
```javascript
// Add to health report
home_assistant: {
  // ... existing fields ...
  
  // NEW: Detailed statistics
  statistics: {
    entities: {
      total: 156,
      by_domain: {
        "sensor": 45,
        "light": 12,
        "switch": 8,
        "binary_sensor": 23,
        // ... etc
      }
    },
    automations: {
      total: 25,
      enabled: 23,
      disabled: 2
    },
    scripts: {
      total: 8,
      enabled: 8
    },
    scenes: {
      total: 5
    },
    helpers: {
      total: 12,
      by_type: {
        "input_number": 3,
        "input_boolean": 5,
        "input_text": 4
      }
    },
    areas: {
      total: 8,
      names: ["Living Room", "Bedroom", "Kitchen", ...]
    },
    devices: {
      total: 42,
      by_manufacturer: {
        "Philips": 8,
        "TP-Link": 5,
        "Sonoff": 3,
        // ... etc
      },
      by_integration: {
        "zigbee": 15,
        "wifi": 12,
        "zwave": 8,
        // ... etc
      }
    },
    integrations: {
      total: 15,
      loaded: 15,
      failed: 0,
      list: [
        { name: "zigbee", version: "1.0.0", config_flow: true },
        { name: "zwave", version: "2.1.0", config_flow: true },
        // ... etc
      ]
    }
  },
  
  // NEW: System information
  system_info: {
    arch: "aarch64",
    platform: "hassos",
    docker_version: "24.0.7",
    supervisor_version: "2024.12.0",
    homeassistant_version: "2025.12.4"
  },
  
  // NEW: Performance metrics
  performance: {
    cpu_percent: 12.5,
    memory_percent: 45.2,
    disk_usage_percent: 17.4
  }
}
```

**How to Collect HA Data:**
1. **Via QEMU Guest Agent** (already implemented in `homeassistant-info-fetcher.nix`)
   - Reads from `/var/lib/havm/ha-info.json`
   - Reads from `/var/lib/havm/ha-metrics.json`

2. **Via HA REST API** (fallback)
   - Use access token from config
   - Call `/api/states`, `/api/config`, `/api/history`
   - Parse response for statistics

**UI Display Sections:**
```
Home Assistant Card:
├─ Status & Version
├─ Statistics Overview
│  ├─ Devices: 42
│  ├─ Integrations: 15
│  ├─ Entities: 156
│  ├─ Automations: 25
│  └─ Areas: 8
├─ Device Breakdown
│  ├─ By Manufacturer (chart)
│  └─ By Integration (chart)
├─ Integration List
│  └─ Show all integrations with status
└─ Performance
   ├─ CPU: 12.5%
   ├─ Memory: 45.2%
   └─ Disk: 17.4%
```

**Files to Modify:**
- `kaliunbox-nix/modules/homeassistant/info-fetcher.nix` (enhance data collection)
- `kaliunbox-nix/modules/health-reporter.nix` (include HA stats in health report)
- `kaliun-connect-api/src/index.js` (display HA statistics)

**Testing:**
- Verify HA statistics are collected
- Verify data displays in UI
- Verify statistics update regularly
- Verify fallback to API if guest agent fails

---

#### **Step 3.3: Enhanced Health Metrics Display**
**Files to modify:**
- `kaliun-connect-api/src/index.js` (UI rendering)

**Improvements:**
1. **Better progress bars** with labels + values
2. **Metric cards** with large numbers
3. **Trend indicators** (up/down arrows)
4. **Historical charts** (if we add history tracking)

**UI Components:**
```html
<!-- Metric Card -->
<div class="metric-card">
  <div class="metric-label">Memory Usage</div>
  <div class="metric-value">31.1%</div>
  <div class="metric-details">4.8 GiB / 15.4 GiB</div>
  <div class="progress-bar" style="width: 31.1%"></div>
</div>
```

**Testing:**
- Verify metrics display correctly
- Verify progress bars are accurate
- Verify values update in real-time

---

### **PHASE 4: Professional UI Upgrade** (Week 4)
**Goal:** Modern, professional UI matching screenshot quality

#### **Step 4.1: Add Tailwind CSS**
**Files to modify:**
- `kaliun-connect-api/src/index.js` (add Tailwind CDN)

**Changes:**
```html
<!-- Add to <head> -->
<script src="https://cdn.tailwindcss.com"></script>
<script>
  tailwind.config = {
    darkMode: 'class',
    theme: {
      extend: {
        colors: {
          kaliun: {
            blue: '#3b82f6',
            dark: '#0a0a0a',
            card: '#1a1a1a',
          }
        }
      }
    }
  }
</script>
```

**Testing:**
- Verify Tailwind loads
- Verify styles apply correctly
- Verify no conflicts with existing styles

---

#### **Step 4.2: Professional Badge Components**
**Files to modify:**
- `kaliun-connect-api/src/index.js` (update badge HTML/CSS)

**Replace current badges with:**
```html
<!-- Professional Badge -->
<span class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium bg-green-500/10 text-green-400 border border-green-500/20">
  <span class="w-1.5 h-1.5 rounded-full bg-green-400"></span>
  Running
</span>
```

**Testing:**
- Verify badges look professional
- Verify all status types have proper styling
- Verify badges are responsive

---

#### **Step 4.3: Enhanced Dashboard Layout**
**Files to modify:**
- `kaliun-connect-api/src/index.js` (dashboard HTML)

**Changes:**
1. Better card spacing (24px gaps)
2. Card headers with icons
3. Two-column responsive layout
4. Better typography hierarchy

**Testing:**
- Verify layout matches screenshot
- Verify responsive on mobile
- Verify proper spacing

---

#### **Step 4.4: Timeline Component Enhancement**
**Files to modify:**
- `kaliun-connect-api/src/index.js` (timeline HTML/CSS)

**Add:**
- Icons for each event type
- Better visual hierarchy
- Clickable items
- Event descriptions

**Testing:**
- Verify timeline looks professional
- Verify icons display correctly
- Verify timeline is scrollable

---

### **PHASE 5: Subscription & Incident System** (Week 5)
**Goal:** Add subscription management and incident tracking

#### **Step 5.1: Subscription System**
**Database:**
```sql
CREATE TABLE subscriptions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id),
  plan_name TEXT NOT NULL, -- 'essential', 'pro', 'enterprise'
  status TEXT NOT NULL, -- 'pending', 'active', 'cancelled', 'past_due'
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  current_period_start TIMESTAMPTZ,
  current_period_end TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE subscription_usage (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  subscription_id UUID NOT NULL REFERENCES subscriptions(id),
  metric_name TEXT NOT NULL, -- 'devices', 'integrations', 'storage_gb'
  current_usage INTEGER DEFAULT 0,
  limit_value INTEGER NOT NULL,
  period_start TIMESTAMPTZ,
  period_end TIMESTAMPTZ,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

**API Endpoints:**
```javascript
GET  /api/v1/subscription
GET  /api/v1/subscription/usage
POST /api/v1/subscription/upgrade
POST /api/v1/subscription/cancel
```

**UI:**
- Subscription status badge
- Plan name display
- Usage progress bars
- Stripe customer link

---

#### **Step 5.2: Incident Tracking**
**Database:**
```sql
CREATE TABLE incidents (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  installation_id UUID NOT NULL REFERENCES installations(id),
  title TEXT NOT NULL,
  description TEXT,
  severity TEXT NOT NULL, -- 'low', 'medium', 'high', 'critical'
  status TEXT NOT NULL DEFAULT 'open', -- 'open', 'investigating', 'resolved', 'closed'
  tags TEXT[],
  created_at TIMESTAMPTZ DEFAULT NOW(),
  resolved_at TIMESTAMPTZ,
  resolved_by UUID REFERENCES users(id)
);
```

**API Endpoints:**
```javascript
GET  /api/v1/installations/:id/incidents
POST /api/v1/installations/:id/incidents
PUT  /api/v1/incidents/:id/resolve
GET  /api/v1/incidents/:id
```

**UI:**
- Incident timeline entries
- Tag system
- Resolution tracking
- Incident details page

---

## Summary: What Each Phase Delivers

### **Phase 1** ✅
- Working log reporting
- Accurate status detection
- Role system foundation
- Basic access control

### **Phase 2** ✅
- Full role-based access
- Installer workflow
- Admin tools
- User management

### **Phase 3** ✅
- Comprehensive hardware stats
- Home Assistant statistics (devices, integrations, entities)
- Enhanced health metrics
- Performance monitoring

### **Phase 4** ✅
- Professional UI (Tailwind)
- Modern badges and components
- Enhanced dashboard layout
- Timeline improvements

### **Phase 5** ✅
- Subscription management
- Incident tracking
- Usage monitoring
- Billing integration

---

## Home Assistant Data Collection - Detailed

### **Current Implementation:**
✅ **Already collecting:**
- HA version
- HAOS version
- Device count
- Integration count
- Status (running/stopped)

### **To Add:**
1. **Entity Statistics**
   - Total entities
   - Entities by domain (sensor, light, switch, etc.)
   - Entity states breakdown

2. **Automation Statistics**
   - Total automations
   - Enabled vs disabled
   - Automation execution counts

3. **Device Details**
   - Device list with names
   - Devices by manufacturer
   - Devices by integration type
   - Device status (online/offline)

4. **Integration Details**
   - Integration list with versions
   - Integration status (loaded/failed)
   - Integration configuration status

5. **Area/Zone Information**
   - Total areas
   - Area names
   - Devices per area

6. **Performance Metrics**
   - HA CPU usage
   - HA memory usage
   - HA disk usage
   - Response times

### **Collection Methods:**
1. **Primary: QEMU Guest Agent** (already implemented)
   - Reads cached data from `/var/lib/havm/ha-info.json`
   - Reads metrics from `/var/lib/havm/ha-metrics.json`
   - Fast, no API calls needed

2. **Fallback: HA REST API**
   - Use access token from config
   - Call `/api/states` for entity count
   - Call `/api/config` for system info
   - Call `/api/history` for performance data

3. **Enhanced: Supervisor API**
   - Call `/api/hassio/core/info` for core info
   - Call `/api/hassio/supervisor/info` for supervisor info
   - Call `/api/hassio/stats` for system stats

---

## Testing Checklist

### **Log Reporting**
- [ ] Verify logs are collected from all services
- [ ] Verify HA logs are extracted from VM
- [ ] Verify cursor tracking works correctly
- [ ] Verify retry mechanism works
- [ ] Verify logs are categorized correctly

### **Status Detection**
- [ ] Verify online status shows correctly
- [ ] Verify offline status shows after timeout
- [ ] Verify timezone handling
- [ ] Verify status history is tracked
- [ ] Verify health reporter is running

### **Role System**
- [ ] Verify home owners only see own installations
- [ ] Verify installers see assigned installations
- [ ] Verify admins see all installations
- [ ] Verify role changes work
- [ ] Verify installer assignment works

---

---

## Missing Features from Professional UI (Screenshot Analysis)

### **✅ Currently Implemented**
- Basic status badges (but need styling improvement)
- Health metrics display
- Service cards
- Timeline component (basic)
- Two-column layout

### **❌ Missing Features**

#### **1. Subscription Management** (HIGH PRIORITY)
- Subscription status badges ("pending", "active")
- Plan display ("Essential $39/mo")
- Usage tracking with progress bars:
  - Devices: "6 / 50"
  - Integrations: "2 / 15"
- Stripe integration link
- Billing management

#### **2. Incident Tracking** (HIGH PRIORITY)
- Incident creation from system events
- Incident timeline entries
- Tag system (color-coded tags)
- Resolution tracking
- Incident details page

#### **3. Professional Badge Styling** (MEDIUM PRIORITY)
- Current badges look unprofessional
- Need: Subtle backgrounds, better borders, proper spacing
- Status dots should be smaller and more refined

#### **4. Enhanced Service Cards** (MEDIUM PRIORITY)
- Service descriptions ("Smart home platform")
- Multiple detail rows (VM IP, Version, OS Version)
- Connection status with info icons
- Better icon styling

#### **5. Remote Access Section** (MEDIUM PRIORITY)
- Dedicated "Remote Access" card
- Connection status display
- Configuration status ("Not configured" vs "Online")
- Setup/configure button

#### **6. Installer Information** (MEDIUM PRIORITY)
- Show installer who claimed device
- Installer contact info
- Clickable to view installer profile
- Only visible when installer assigned

#### **7. Better Progress Bars** (LOW PRIORITY)
- Label + percentage on same line
- Actual values below bar
- Better color gradients
- Smooth animations

#### **8. Enhanced Timeline** (LOW PRIORITY)
- Icons for each event type
- Better visual hierarchy
- Clickable timeline items
- Event descriptions

#### **9. Typography & Spacing** (LOW PRIORITY)
- Consistent 8px grid system
- Better font hierarchy
- Improved line heights
- Better color contrast

---

## UI Framework Recommendation

### **Option 1: Tailwind CSS (Recommended)**
**Pros:**
- Professional, modern design system
- Utility-first (fast development)
- Responsive by default
- Great documentation
- Can use via CDN for quick start

**Cons:**
- Learning curve if not familiar
- Larger CSS file (but can purge unused)

**Implementation:**
```html
<!-- Add to head -->
<script src="https://cdn.tailwindcss.com"></script>
```

**Example Badge:**
```html
<span class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium bg-green-500/10 text-green-400 border border-green-500/20">
  <span class="w-1.5 h-1.5 rounded-full bg-green-400"></span>
  Running
</span>
```

---

### **Option 2: shadcn/ui Components**
**Pros:**
- Pre-built professional components
- Accessible by default
- Highly customizable
- Modern React patterns

**Cons:**
- Requires React (major refactor)
- More complex setup

---

### **Option 3: Keep Current + Enhance**
**Pros:**
- No framework migration
- Full control
- Smaller bundle size

**Cons:**
- More manual work
- Harder to maintain consistency
- Need to write all styles manually

**Recommendation:** Use Tailwind CSS via CDN for quick professional upgrade, then consider build process later.

---

## Notes

- **Current codebase has NO role system** - this is a major architectural gap
- **Log reporting has multiple failure points** - needs comprehensive debugging
- **Status detection is fragile** - 10-minute timeout with no retry mechanism
- **No installer workflow** - installers can't manage multiple customers
- **No admin tools** - can't manage users or view system-wide data
- **UI is basic/inline CSS** - needs professional framework (Tailwind recommended)
- **Missing subscription system** - no billing/plan management
- **Missing incident tracking** - no way to track and resolve issues
- **Badges look unprofessional** - need modern styling

This architecture document should be reviewed and approved before implementation begins.

