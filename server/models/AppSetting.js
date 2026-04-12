const { DataTypes } = require('sequelize');
const sequelize = require('../db');

const AppSetting = sequelize.define('AppSetting', {
  key: {
    type: DataTypes.STRING,
    primaryKey: true,
    allowNull: false
  },
  value: {
    type: DataTypes.TEXT,
    allowNull: false
  }
}, {
  tableName: 'app_settings',
  timestamps: true
});

module.exports = AppSetting;
