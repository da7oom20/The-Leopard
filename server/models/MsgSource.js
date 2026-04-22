const { DataTypes } = require('sequelize');
const sequelize = require('../db');

const MsgSource = sequelize.define('MsgSource', {
  client: { type: DataTypes.STRING, allowNull: false },
  siemType: { type: DataTypes.STRING, allowNull: false, defaultValue: 'logrhythm' },
  filterType: { type: DataTypes.STRING, allowNull: false },
  listId: { type: DataTypes.INTEGER, allowNull: true },
  guid: { type: DataTypes.STRING, allowNull: true },
  name: { type: DataTypes.STRING, allowNull: true },
  listType: { type: DataTypes.STRING, allowNull: true }
}, {
  tableName: 'msgsources',
  indexes: [
    { fields: ['client', 'siemType', 'filterType'] }
  ]
});

module.exports = MsgSource;
