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

- [ ] Create sale / bill with line items
- [ ] Apply item-level and bill-level discounts
- [ ] GST auto-calculation (CGST/SGST/IGST based on customer state)
- [ ] Multiple payment modes (cash, UPI, card, credit)
- [ ] Auto-deduct stock via inventory movements (stock_out)
- [ ] Link sale to customer (optional walk-in support)
- [ ] Sale return / credit note
- [ ] Hold & resume bill
- [ ] Daily cash register open/close

### Phase 3 — Invoicing / Billing
> *GST-compliant invoice generation*

- [ ] Auto-generate invoice number series (per financial year)
- [ ] Tax invoice with CGST/SGST/IGST breakdown
- [ ] HSN-wise tax summary (required for GST returns)
- [ ] Credit notes for returns
- [ ] Delivery challan generation
- [ ] Quotation / estimate generation
- [ ] Invoice PDF export

### Phase 4 — Audit Logs
> *Track who did what, when, with before/after diffs*

- [ ] Audit service (module, action, user, before/after snapshots)
- [ ] Auto-log on every create/update/delete across all modules
- [ ] Admin-only audit log viewer with filters (module, user, date range)
- [ ] Retention policy (TTL index for auto-cleanup)

### Phase 5 — Stores / Locations
> *Multi-location inventory management*

- [ ] Store CRUD (name, address, manager, contact)
- [ ] Assign items to specific stores
- [ ] Stock transfers between stores
- [ ] Store-wise stock summary
- [ ] Store-wise POS and sales reports

### Phase 6 — Reports / Dashboard
> *The owner's view — business intelligence*

- [ ] Daily / weekly / monthly sales summary
- [ ] Top selling items
- [ ] Low stock alerts dashboard
- [ ] Vendor payment dues
- [ ] Customer outstanding balances
- [ ] Profit margin reports
- [ ] Category-wise sales breakdown
- [ ] Export to CSV / Excel

### Phase 7 — Profile & Password Management
> *User self-service*

- [ ] Change password (mandatory on first login with temp password)
- [ ] Update profile (name, phone, avatar)
- [ ] Forgot password / reset via email or OTP
- [ ] Session management (list active sessions, logout all)

---

## Future Considerations

- **Mobile API optimizations** — lightweight endpoints for Android/iOS POS app
- **Webhooks / Notifications** — low stock alerts, payment reminders via WhatsApp/SMS
- **Multi-currency** — if expanding beyond India
- **Barcode scanning API** — lookup items by barcode from POS app
- **E-invoice integration** — direct GST portal submission (mandatory for turnover > 5 Cr)
