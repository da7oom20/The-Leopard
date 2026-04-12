const { DataTypes } = require('sequelize');
const sequelize = require('../db');

const QueryTemplate = sequelize.define('QueryTemplate', {
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
  template: {
    type: DataTypes.TEXT,
    allowNull: false
  },
  description: {
    type: DataTypes.STRING,
    allowNull: true
  },
  isActive: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  }
}, {
  tableName: 'query_templates',
  timestamps: true
});

module.exports = QueryTemplate;
