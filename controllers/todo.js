const db = require("../models");

const getAllTodos = async (req, res) => {
  const allTodos = await db.Todo.findAll({ where: { user_id: req.user.id }, attributes: ["id", "task"] });
  res.status(200).send(allTodos);
};

const getTodoById = async (req, res) => {
  const targetTodo = await db.Todo.findOne({ where: { id: req.params.id }});
  if (targetTodo && targetTodo.user_id === req.user.id) {
    res.status(200).send(targetTodo);
  } else {
    res.status(404).send({ message: "Not found todo" });
  }
};

const createTodo = async (req, res) => {
  const { task } = req.body;
  const newTodo = await db.Todo.create({
    task,
    user_id: req.user.id,
  });

  res.status(201).send(newTodo);
};

const updateTodo = async (req, res) => {
  const targetTodo = await db.Todo.findOne({ where: { id: req.params.id } });

  if (targetTodo && targetTodo.user_id === req.user.id) {
    await targetTodo.update({ task: req.body.task });
    res.status(200).send({ message: "Already updated" });
  } else {
    res.status(404).send({ message: "Not found" });
  }
};

const deleteTodo = async (req, res) => {
  const targetTodo = await db.Todo.findOne({ where: { id: req.params.id } });

  if (targetTodo && targetTodo.user_id === req.user.id) {
    await targetTodo.destroy();
    res.status(200).send({ message: "Already deleted" });
  } else {
    res.status(404).send({ message: "Not found" });
  }
};

module.exports = {
  getAllTodos,
  getTodoById,
  createTodo,
  updateTodo,
  deleteTodo
};