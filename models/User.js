module.exports = (sequelize, DataTypes) => {
    const User = sequelize.define("User", {
      username: {
        unique: true,
        allowNull: false,
        type: DataTypes.STRING
      },
      password: {
        allowNull: false,
        type: DataTypes.STRING
      },
      name: DataTypes.STRING
    },{
        tableName: "users",
        timestamps: false
    });
  
    User.associate = models => {
      User.hasMany(models.Todo, { foreignKey: "user_id" });
    };
  
    return User;
  }