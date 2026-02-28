# Corely Enterprise System — Product Roadmap

## Current Status (v1.0)

All modules below are built, tested, and running.

| Module | Collection(s) | Endpoints | Status |
|--------|---------------|-----------|--------|
| **Config** | — | — | Done |
| **Auth** | `{slug}_users` | `/api/v1/auth/login` | Done |
| **Users** | `{slug}_users` | CRUD at `/api/v1/users` | Done |
| **Items / Products** | `{slug}_items` | CRUD at `/api/v1/items` | Done |
| **Inventory** | `{slug}_stock_movements`, `{slug}_purchase_entries` | Movements, purchases, adjustments, stock summary, ledger at `/api/v1/inventory` | Done |
| **Customers** | `{slug}_customers` | CRUD at `/api/v1/customers` | Done |
| **Vendors** | `{slug}_vendors` | CRUD at `/api/v1/vendors` | Done |
| **Organization** | `organizations` (global) | Setup + slug check at `/base/api/v1` | Done |
| **RBAC** | — | 4 roles (super_admin, admin, manager, employee) | Done |
| **Middleware** | — | JWT decode + RBAC enforcement | Done |
| **Request Logger** | — | Logs every request with method, path, status, duration | Done |

---

## Roadmap

### Phase 2 — POS (Point of Sale)
> *The core revenue flow — sell items to customers*

- [x] Create sale / bill with line items
- [x] Apply item-level and bill-level discounts
- [x] GST auto-calculation (CGST/SGST/IGST based on customer state)
- [x] Multiple payment modes (cash, UPI, card, credit)
- [x] Auto-deduct stock via inventory movements (stock_out)
- [x] Link sale to customer (optional walk-in support)
- [x] Sale return / credit note
- [x] Hold & resume bill
- [x] Daily cash register open/close

### Phase 3 — Invoicing / Billing
> *GST-compliant invoice generation*

- [x] Auto-generate invoice number series (per financial year)
- [x] Tax invoice with CGST/SGST/IGST breakdown
- [x] HSN-wise tax summary (required for GST returns)
- [x] Credit notes for returns
- [x] Delivery challan generation
- [x] Quotation / estimate generation
- [x] Invoice PDF export

### Phase 4 — Audit Logs
> *Track who did what, when, with before/after diffs*

- [x] Audit service (module, action, user, before/after snapshots)
- [x] Auto-log on every create/update/delete across all modules
- [x] Admin-only audit log viewer with filters (module, user, date range)
- [x] Retention policy (TTL index for auto-cleanup)

### Phase 5 — Stores / Locations
> *Multi-location inventory management*

- [x] Store CRUD (name, address, manager, contact)
- [x] Assign items to specific stores
- [x] Stock transfers between stores
- [x] Store-wise stock summary
- [x] Store-wise POS and sales reports

### Phase 6 — Reports / Dashboard
> *The owner's view — business intelligence*

- [x] Daily / weekly / monthly sales summary
- [x] Top selling items
- [x] Low stock alerts dashboard
- [x] Vendor payment dues
- [x] Customer outstanding balances
- [x] Profit margin reports
- [x] Category-wise sales breakdown
- [x] Export to CSV / Excel

### Phase 7 — Profile & Password Management
> *User self-service*

- [x] Change password (mandatory on first login with temp password)
- [x] Update profile (name, phone, avatar)
- [x] Forgot password / reset via email or OTP
- [x] Session management (list active sessions, logout all)

---

## Future Considerations

- **Mobile API optimizations** — lightweight endpoints for Android/iOS POS app
- **Webhooks / Notifications** — low stock alerts, payment reminders via WhatsApp/SMS
- **Multi-currency** — if expanding beyond India
- **Barcode scanning API** — lookup items by barcode from POS app
- **E-invoice integration** — direct GST portal submission (mandatory for turnover > 5 Cr)
