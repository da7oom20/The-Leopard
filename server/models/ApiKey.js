const { DataTypes } = require('sequelize');
const sequelize = require('../db');
const { encrypt, decrypt, encryptJsonFields, decryptJsonFields } = require('../utils/crypto');

const ApiKey = sequelize.define('ApiKey', {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  client: {
    type: DataTypes.STRING,
    allowNull: false
  },
  siemType: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      isIn: [['logrhythm', 'splunk', 'qradar', 'manageengine', 'wazuh', 'elastic']]
    }
  },
  apiHost: {
    type: DataTypes.STRING,
    allowNull: false
  },
  apiKey: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  username: {
    type: DataTypes.STRING,
    allowNull: true
  },
  password: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  port: {
    type: DataTypes.INTEGER,
    allowNull: true
  },
  verifySSL: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },
  extraConfig: {
    type: DataTypes.JSON,
    allowNull: true,
    defaultValue: {}
  },
  isActive: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },
  lastTestedAt: {
    type: DataTypes.DATE,
    allowNull: true
  },
  lastTestStatus: {
    type: DataTypes.STRING,
    allowNull: true
  }
}, {
  tableName: 'apikeys',
  timestamps: true,
  indexes: [
    { fields: ['isActive'] },
    { fields: ['client'] }
  ],
  hooks: {
    beforeCreate(instance) {
      if (instance.apiKey) instance.apiKey = encrypt(instance.apiKey);
      if (instance.password) instance.password = encrypt(instance.password);
      if (instance.extraConfig) instance.extraConfig = encryptJsonFields(instance.extraConfig);
    },
    beforeUpdate(instance) {
      if (instance.changed('apiKey') && instance.apiKey) instance.apiKey = encrypt(instance.apiKey);
      if (instance.changed('password') && instance.password) instance.password = encrypt(instance.password);
      if (instance.changed('extraConfig') && instance.extraConfig) instance.extraConfig = encryptJsonFields(instance.extraConfig);
    },
    afterFind(results) {
      if (!results) return;
      const rows = Array.isArray(results) ? results : [results];
      for (const row of rows) {
        if (row.apiKey) row.apiKey = decrypt(row.apiKey);
        if (row.password) row.password = decrypt(row.password);
        if (row.extraConfig) row.extraConfig = decryptJsonFields(row.extraConfig);
      }
    }
  }
});

module.exports = ApiKey;
