const { DataTypes } = require('sequelize');
const sequelize = require('../db');

const FieldMapping = sequelize.define('FieldMapping', {
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
  filterType: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      isIn: [['IP', 'Hash', 'Domain', 'URL', 'Email', 'FileName']]
    }
  },
  fields: {
    type: DataTypes.JSON,
    allowNull: false
  },
  logSource: {
    type: DataTypes.STRING,
    allowNull: true
  },
  isApproved: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  }
}, {
  tableName: 'field_mappings',
  timestamps: true,
  indexes: [
    // Used by logsDigging to find custom fields for a client+siem+filterType
    { fields: ['client', 'siemType', 'filterType'] },
    // Used by approval status filtering
    { fields: ['isApproved'] }
  ]
});

module.exports = FieldMapping;
