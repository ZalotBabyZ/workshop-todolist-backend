module.exports = (sequelize, DataTypes) => {
    const Todo = sequelize.define("Todo", {
      task: DataTypes.STRING
    }, {
      tableName: "todos",
      timestamps: false
    });
  
    Todo.associate = models => {
      Todo.belongsTo(models.User, { foreignKey: "user_id" });
    };
  
    return Todo;
  }