(function (global) {
  const PERMISSION_DEFS = Object.freeze([
    { key: 'budget' },
    { key: 'budget_dashboard', parent: 'budget' },
    { key: 'income_bankeur', parent: 'ledger' },
    { key: 'orders' },
    { key: 'orders_itemize', parent: 'orders' },
    { key: 'orders_reconciliation', parent: 'orders' },
    { key: 'ledger' },
    { key: 'ledger_wiseeur', parent: 'ledger' },
    { key: 'ledger_wiseusd', parent: 'ledger' },
    { key: 'ledger_money_transfers' },
    { key: 'archive' },
    { key: 'settings' },
    { key: 'settings_roles', parent: 'settings' },
    { key: 'settings_backlog', parent: 'settings' },
    { key: 'settings_numbering', parent: 'settings' },
    { key: 'settings_grandlodge', parent: 'settings' },
    { key: 'settings_email_notifications', parent: 'settings' },
    { key: 'settings_backup', parent: 'settings' },
    { key: 'settings_audit', parent: 'settings' },
  ]);

  const PERMISSION_FORM_ROWS = Object.freeze([
    { key: 'budget', idBase: 'Budget', label: 'Budget', group: 'main' },
    { key: 'budget_dashboard', idBase: 'BudgetDashboard', label: 'Dashboard', group: 'sub' },
    { key: 'orders', idBase: 'Orders', label: 'Payment Orders', group: 'main' },
    { key: 'orders_itemize', idBase: 'OrdersItemize', label: 'Itemize Payment Order', group: 'sub' },
    { key: 'orders_reconciliation', idBase: 'OrdersReconciliation', label: 'Reconciliation', group: 'sub' },
    { key: 'ledger', idBase: 'Ledger', label: 'Ledger', group: 'main' },
    { key: 'income_bankeur', idBase: 'IncomeBankeur', label: 'BankEUR', group: 'sub' },
    { key: 'ledger_wiseeur', idBase: 'LedgerWiseEur', label: 'wiseEUR', group: 'sub' },
    { key: 'ledger_wiseusd', idBase: 'LedgerWiseUsd', label: 'wiseUSD', group: 'sub' },
    { key: 'ledger_money_transfers', idBase: 'LedgerMoneyTransfers', label: 'Money Transfers', group: 'main' },
    { key: 'archive', idBase: 'Archive', label: 'Archive', group: 'main' },
    { key: 'settings', idBase: 'Settings', label: 'Admin Settings', group: 'main' },
    { key: 'settings_roles', idBase: 'SettingsRoles', label: 'User Roles', group: 'sub' },
    { key: 'settings_backlog', idBase: 'SettingsBacklog', label: 'Backlog', group: 'sub' },
    { key: 'settings_numbering', idBase: 'SettingsNumbering', label: 'PO & MT Numbering', group: 'sub' },
    { key: 'settings_grandlodge', idBase: 'SettingsGrandLodge', label: 'GL Information', group: 'sub' },
    { key: 'settings_email_notifications', idBase: 'SettingsEmailNotifications', label: 'Email Notifications', group: 'sub' },
    { key: 'settings_backup', idBase: 'SettingsBackup', label: 'Backup', group: 'sub' },
    { key: 'settings_audit', idBase: 'SettingsAudit', label: 'Audit Log', group: 'sub' },
  ]);

  const ACCESS_LEVELS = Object.freeze(['none', 'read', 'write', 'create', 'delete', 'full']);
  const ACCESS_LEVEL_RANK = Object.freeze({
    none: 0,
    read: 1,
    write: 2,
    create: 3,
    delete: 4,
    full: 5,
  });
  const ACCESS_LEVEL_CAPABILITIES = Object.freeze({
    none: Object.freeze({ read: false, write: false, create: false, delete: false, full: false }),
    read: Object.freeze({ read: true, write: false, create: false, delete: false, full: false }),
    write: Object.freeze({ read: true, write: true, create: false, delete: false, full: false }),
    create: Object.freeze({ read: true, write: true, create: true, delete: false, full: false }),
    delete: Object.freeze({ read: true, write: true, create: true, delete: true, full: false }),
    full: Object.freeze({ read: true, write: true, create: true, delete: true, full: true }),
  });

  const STRICT_EXPLICIT_PERMISSION_KEYS = new Set([
    'income_bankeur',
    'ledger_money_transfers',
    'orders_itemize',
    'orders_reconciliation',
  ]);

  const ADMIN_ROLE_VALUES = Object.freeze([
    'admin',
    'administrator',
    'site administrator',
    'super admin',
  ]);

  const ROLE_LABEL_ALIASES = Object.freeze({
    'grand secretary': 'Grand Secretary',
    'assist. grand secretary': 'Assist. Grand Secretary',
    'assist grand secretary': 'Assist. Grand Secretary',
    'assistant grand secretary': 'Assist. Grand Secretary',
    'asst. grand secretary': 'Assist. Grand Secretary',
    'asst grand secretary': 'Assist. Grand Secretary',
    'grand master': 'Grand Master',
    'grand treasurer': 'Grand Treasurer',
    'assist. grand treasurer': 'Assist. Grand Treasurer',
    'assist grand treasurer': 'Assist. Grand Treasurer',
    'assistant grand treasurer': 'Assist. Grand Treasurer',
    'asst. grand treasurer': 'Assist. Grand Treasurer',
    'asst grand treasurer': 'Assist. Grand Treasurer',
  });

  const ROLE_OPTIONS = Object.freeze([
    'Grand Master',
    'Deputy Grand Master',
    'Sr. Grand Warden',
    'Jr. Grand Warden',
    'Grand Secretary',
    'Assist. Grand Secretary',
    'Grand Treasurer',
    'Assist. Grand Treasurer',
    'Auditor',
  ]);

  const PAGE_PERMISSION_MAP = Object.freeze({
    'budget.html': 'budget',
    'budget_dashboard.html': 'budget_dashboard',
    'income.html': 'income_bankeur',
    'wise_eur.html': 'ledger_wiseeur',
    'wise_usd.html': 'ledger_wiseusd',
    'menu.html': 'orders',
    'reconciliation.html': 'orders_reconciliation',
    'grand_secretary_ledger.html': 'ledger',
    'money_transfers.html': 'ledger_money_transfers',
    'money_transfer.html': 'ledger_money_transfers',
    'archive.html': 'archive',
    'settings.html': 'settings',
  });

  const BOOTSTRAP_ADMIN = Object.freeze({
    id: 'user_admin_pass_v1',
    username: 'admin.pass',
    password: 'acgl1962ADM',
    salt: 'acgl_fms_admin_v1',
    defaultPermissions: Object.freeze({
      budget: 'full',
      income_bankeur: 'full',
      orders: 'full',
      ledger: 'full',
      ledger_money_transfers: 'full',
      archive: 'full',
      settings: 'full',
    }),
  });

  const WORKFLOW_ROLE_RULES = Object.freeze({
    withField: Object.freeze({
      Requestor: Object.freeze(['Grand Secretary', 'Assist. Grand Secretary']),
      'Grand Secretary': Object.freeze(['Grand Secretary', 'Assist. Grand Secretary']),
      'Grand Master': Object.freeze(['Grand Secretary', 'Grand Master']),
      'Grand Treasurer': Object.freeze(['Grand Secretary', 'Grand Master', 'Grand Treasurer', 'Assist. Grand Treasurer']),
    }),
    statusField: Object.freeze({
      Requestor: Object.freeze(['Grand Secretary', 'Assist. Grand Secretary', 'Grand Master']),
      'Grand Secretary': Object.freeze(['Grand Secretary', 'Assist. Grand Secretary', 'Grand Master']),
      'Grand Master': Object.freeze(['Grand Secretary', 'Grand Master']),
      'Grand Treasurer': Object.freeze(['Grand Secretary', 'Grand Master', 'Grand Treasurer', 'Assist. Grand Treasurer']),
    }),
  });

  function normalizeAccessLevel(value) {
    if (value === true) return 'full';
    if (value === false || value == null) return 'none';
    const normalized = String(value).trim().toLowerCase();
    if (normalized === 'full' || normalized === 'fullaccess' || normalized === 'admin') return 'full';
    if (normalized === 'delete' || normalized === 'remove') return 'delete';
    if (normalized === 'create' || normalized === 'add') return 'create';
    if (normalized === 'write' || normalized === 'edit' || normalized === 'partial' || normalized === 'limited' || normalized === 'some') return 'write';
    if (normalized === 'read' || normalized === 'readonly' || normalized === 'read-only') return 'read';
    if (normalized === 'none' || normalized === 'no' || normalized === 'noaccess') return 'none';
    return 'none';
  }

  function normalizeRoleLabel(roleValue) {
    const raw = String(roleValue || '').trim();
    if (!raw) return '';
    return ROLE_LABEL_ALIASES[raw.toLowerCase()] || raw;
  }

  function isAdminRoleValue(roleValue) {
    const normalized = String(roleValue || '').trim().toLowerCase();
    if (!normalized) return false;
    return ADMIN_ROLE_VALUES.includes(normalized);
  }

  function getRoleAccessPreset(roleName) {
    const role = normalizeRoleLabel(roleName);
    return role ? ROLE_ACCESS_PRESETS[role] || null : null;
  }

  function canRoleManageWorkflowField(fieldKey, roleName, currentWith) {
    const rules = WORKFLOW_ROLE_RULES[fieldKey] || {};
    const allowedRoles = rules[String(currentWith || '').trim()] || [];
    const normalizedRole = normalizeRoleLabel(roleName);
    return Boolean(normalizedRole && allowedRoles.includes(normalizedRole));
  }

  const ROLE_ACCESS_PRESETS = Object.freeze({
    'Grand Secretary': Object.freeze(Object.fromEntries(PERMISSION_FORM_ROWS.map((row) => [row.idBase, 'full']))),
    'Assist. Grand Secretary': Object.freeze(Object.fromEntries(PERMISSION_FORM_ROWS.map((row) => [row.idBase, 'full']))),
    Auditor: Object.freeze({
      Budget: 'read',
      BudgetDashboard: 'read',
      Orders: 'read',
      OrdersItemize: 'read',
      OrdersReconciliation: 'read',
      Ledger: 'read',
      IncomeBankeur: 'read',
      LedgerWiseEur: 'read',
      LedgerWiseUsd: 'read',
      LedgerMoneyTransfers: 'read',
      Archive: 'read',
      Settings: 'none',
      SettingsRoles: 'none',
      SettingsBacklog: 'none',
      SettingsNumbering: 'none',
      SettingsGrandLodge: 'none',
      SettingsBackup: 'none',
      SettingsAudit: 'none',
    }),
    'Sr. Grand Warden': Object.freeze({
      Budget: 'read',
      BudgetDashboard: 'read',
      Orders: 'read',
      OrdersItemize: 'read',
      OrdersReconciliation: 'read',
      Ledger: 'read',
      IncomeBankeur: 'read',
      LedgerWiseEur: 'read',
      LedgerWiseUsd: 'read',
      LedgerMoneyTransfers: 'read',
      Archive: 'read',
      Settings: 'read',
      SettingsRoles: 'none',
      SettingsBacklog: 'full',
      SettingsNumbering: 'read',
      SettingsGrandLodge: 'full',
      SettingsBackup: 'read',
      SettingsAudit: 'read',
    }),
    'Jr. Grand Warden': Object.freeze({
      Budget: 'read',
      BudgetDashboard: 'read',
      Orders: 'read',
      OrdersItemize: 'read',
      OrdersReconciliation: 'read',
      Ledger: 'read',
      IncomeBankeur: 'read',
      LedgerWiseEur: 'read',
      LedgerWiseUsd: 'read',
      LedgerMoneyTransfers: 'read',
      Archive: 'read',
      Settings: 'read',
      SettingsRoles: 'none',
      SettingsBacklog: 'full',
      SettingsNumbering: 'read',
      SettingsGrandLodge: 'full',
      SettingsBackup: 'read',
      SettingsAudit: 'read',
    }),
    'Grand Master': Object.freeze({
      Budget: 'read',
      BudgetDashboard: 'read',
      Orders: 'read',
      OrdersItemize: 'create',
      OrdersReconciliation: 'read',
      Ledger: 'read',
      IncomeBankeur: 'read',
      LedgerWiseEur: 'read',
      LedgerWiseUsd: 'read',
      LedgerMoneyTransfers: 'read',
      Archive: 'read',
      Settings: 'read',
      SettingsRoles: 'none',
      SettingsBacklog: 'full',
      SettingsNumbering: 'read',
      SettingsGrandLodge: 'full',
      SettingsBackup: 'read',
      SettingsAudit: 'read',
    }),
    'Deputy Grand Master': Object.freeze({
      Budget: 'read',
      BudgetDashboard: 'read',
      Orders: 'read',
      OrdersItemize: 'create',
      OrdersReconciliation: 'read',
      Ledger: 'read',
      IncomeBankeur: 'read',
      LedgerWiseEur: 'read',
      LedgerWiseUsd: 'read',
      LedgerMoneyTransfers: 'read',
      Archive: 'read',
      Settings: 'read',
      SettingsRoles: 'none',
      SettingsBacklog: 'full',
      SettingsNumbering: 'read',
      SettingsGrandLodge: 'full',
      SettingsBackup: 'read',
      SettingsAudit: 'read',
    }),
    'Grand Treasurer': Object.freeze({
      Budget: 'write',
      BudgetDashboard: 'read',
      Orders: 'read',
      OrdersItemize: 'none',
      OrdersReconciliation: 'read',
      Ledger: 'read',
      IncomeBankeur: 'create',
      LedgerWiseEur: 'create',
      LedgerWiseUsd: 'create',
      LedgerMoneyTransfers: 'write',
      Archive: 'read',
      Settings: 'read',
      SettingsRoles: 'none',
      SettingsBacklog: 'full',
      SettingsNumbering: 'read',
      SettingsGrandLodge: 'full',
      SettingsBackup: 'read',
      SettingsAudit: 'read',
    }),
    'Assist. Grand Treasurer': Object.freeze({
      Budget: 'write',
      BudgetDashboard: 'read',
      Orders: 'read',
      OrdersItemize: 'none',
      OrdersReconciliation: 'read',
      Ledger: 'read',
      IncomeBankeur: 'create',
      LedgerWiseEur: 'create',
      LedgerWiseUsd: 'create',
      LedgerMoneyTransfers: 'write',
      Archive: 'read',
      Settings: 'read',
      SettingsRoles: 'none',
      SettingsBacklog: 'full',
      SettingsNumbering: 'read',
      SettingsGrandLodge: 'full',
      SettingsBackup: 'read',
      SettingsAudit: 'read',
    }),
  });

  global.ACGL_USER_ROLES = Object.freeze({
    ACCESS_LEVELS,
    ACCESS_LEVEL_RANK,
    ACCESS_LEVEL_CAPABILITIES,
    ADMIN_ROLE_VALUES,
    BOOTSTRAP_ADMIN,
    PAGE_PERMISSION_MAP,
    PERMISSION_DEFS,
    PERMISSION_FORM_ROWS,
    ROLE_ACCESS_PRESETS,
    ROLE_OPTIONS,
    STRICT_EXPLICIT_PERMISSION_KEYS,
    WORKFLOW_ROLE_RULES,
    canRoleManageWorkflowField,
    getRoleAccessPreset,
    isAdminRoleValue,
    normalizeAccessLevel,
    normalizeRoleLabel,
  });
})(window);