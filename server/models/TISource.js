const { DataTypes } = require('sequelize');
const sequelize = require('../db');
const { encrypt, decrypt } = require('../utils/crypto');

const TISource = sequelize.define('TISource', {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false
  },
  platformType: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      isIn: [[
        'otx', 'misp', 'phishtank',
        'threatfox', 'urlhaus', 'malwarebazaar', 'feodotracker', 'sslbl',
        'openphish', 'blocklist_de', 'emergingthreats', 'spamhaus_drop',
        'firehol_l1', 'talos', 'crowdsec',
        'c2intelfeeds', 'bambenek_c2', 'digitalside'
      ]]
    }
  },
  apiUrl: {
    type: DataTypes.STRING,
    allowNull: true
  },
  apiKey: {
    type: DataTypes.TEXT,
    allowNull: true
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
  },
  extraConfig: {
    type: DataTypes.JSON,
    allowNull: true,
    defaultValue: {}
  }
}, {
  tableName: 'ti_sources',
  timestamps: true,
  hooks: {
    beforeCreate(instance) {
      if (instance.apiKey) instance.apiKey = encrypt(instance.apiKey);
    },
    beforeUpdate(instance) {
      if (instance.changed('apiKey') && instance.apiKey) instance.apiKey = encrypt(instance.apiKey);
    },
    afterFind(results) {
      if (!results) return;
      const rows = Array.isArray(results) ? results : [results];
      for (const row of rows) {
        if (row.apiKey) row.apiKey = decrypt(row.apiKey);
      }
    }
  }
});

module.exports = TISource;
