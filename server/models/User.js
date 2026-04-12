const { DataTypes } = require('sequelize');
const sequelize = require('../db');
const { encrypt, decrypt } = require('../utils/crypto');

const User = sequelize.define('User', {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  username: { type: DataTypes.STRING, unique: true },
  passwordHash: DataTypes.STRING,
  role: {
    type: DataTypes.ENUM('admin', 'analyst', 'viewer'),
    defaultValue: 'analyst',
    allowNull: false,
  },
  isActive: {
    type: DataTypes.BOOLEAN,
    defaultValue: true,
    allowNull: false,
  },
  // Feature permissions (default: enabled for all users)
  canSearch: { type: DataTypes.BOOLEAN, defaultValue: true, allowNull: false },
  canHunt: { type: DataTypes.BOOLEAN, defaultValue: true, allowNull: false },
  canExport: { type: DataTypes.BOOLEAN, defaultValue: true, allowNull: false },
  canViewRepo: { type: DataTypes.BOOLEAN, defaultValue: true, allowNull: false },
  // Admin permissions (default: disabled, grant explicitly)
  canRecon: { type: DataTypes.BOOLEAN, defaultValue: false, allowNull: false },
  canManageSIEM: { type: DataTypes.BOOLEAN, defaultValue: false, allowNull: false },
  canManageTI: { type: DataTypes.BOOLEAN, defaultValue: false, allowNull: false },
  canManageMappings: { type: DataTypes.BOOLEAN, defaultValue: false, allowNull: false },
  canManageUsers: { type: DataTypes.BOOLEAN, defaultValue: false, allowNull: false },
  canManageSecurity: { type: DataTypes.BOOLEAN, defaultValue: false, allowNull: false },
  // Session invalidation: tokens issued before this timestamp are rejected
  tokenIssuedAfter: {
    type: DataTypes.DATE,
    allowNull: true,
  },
  // MFA fields
  mfaEnabled: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false,
  },
  mfaSecret: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  mfaBackupCodes: {
    type: DataTypes.JSON,
    allowNull: true,
  },
}, {
  tableName: 'users',
  hooks: {
    beforeCreate(instance) {
      if (instance.mfaSecret) instance.mfaSecret = encrypt(instance.mfaSecret);
    },
    beforeUpdate(instance) {
      if (instance.changed('mfaSecret') && instance.mfaSecret) instance.mfaSecret = encrypt(instance.mfaSecret);
    },
    afterFind(results) {
      if (!results) return;
      const rows = Array.isArray(results) ? results : [results];
      for (const row of rows) {
        if (row.mfaSecret) row.mfaSecret = decrypt(row.mfaSecret);
      }
    }
  }
});

module.exports = User;
