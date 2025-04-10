import random
from typing import List

from pydantic import BaseModel
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, index=True) # добавлен индекс
    password_hash = Column(String(255))

class GraphInput(BaseModel):
    nodes: List[int]
    edges: List[List[int]]

class PathResult(BaseModel):
    path: List[int]
    total_distance: float

class Graph:
    def __init__(self, adj_matrix):
        self.adj_matrix = adj_matrix
        self.n = len(adj_matrix)

    def get_neighbors(self, i):
        return [j for j in range(self.n) if self.adj_matrix[i][j] != float('inf') and i != j]

    def get_cost(self, i, j):
        return self.adj_matrix[i][j]

class ACO:
    def __init__(self, ant_count, generations, alpha, beta, rho, Q):
        self.ant_count = ant_count
        self.generations = generations
        self.alpha = alpha
        self.beta = beta
        self.rho = rho
        self.Q = Q

    def solve(self, graph):
        best_path = None
        best_cost = float('inf')
        pheromone = [[1.0 for _ in range(graph.n)] for _ in range(graph.n)]

        for _ in range(self.generations):
            ants = []
            for _ in range(self.ant_count):
                path = self.construct_path(graph, pheromone)
                if not path:
                    continue
                cost = self.calculate_cost(graph, path)
                if cost < best_cost:
                    best_cost = cost
                    best_path = path
                ants.append((path, cost))

            self.update_pheromones(graph, pheromone, ants)

        return best_path, best_cost

    def construct_path(self, graph, pheromone):
        path = []
        start = random.randint(0, graph.n - 1)
        path.append(start)
        while len(path) < graph.n:
            current = path[-1]
            neighbors = graph.get_neighbors(current)
            if not neighbors:
                return None
            probabilities = []
            total = 0.0
            for neighbor in neighbors:
                if neighbor in path:
                    continue
                tau = pheromone[current][neighbor] ** self.alpha
                eta = (1.0 / graph.get_cost(current, neighbor)) ** self.beta
                prob = tau * eta
                probabilities.append((neighbor, prob))
                total += prob
            if not probabilities:
                return None
            probabilities = [(n, p/total) for n, p in probabilities]
            next_node = self.select_next_node(probabilities)
            path.append(next_node)
        return path

    def select_next_node(self, probabilities):
        rand = random.random()
        cumulative = 0.0
        for node, prob in probabilities:
            cumulative += prob
            if rand <= cumulative:
                return node
        return probabilities[-1][0]

    def calculate_cost(self, graph, path):
        return sum(graph.get_cost(path[i], path[i+1]) for i in range(len(path)-1))


    def update_pheromones(self, graph, pheromone, ants):
        for i in range(graph.n):
            for j in range(graph.n):
                pheromone[i][j] *= (1 - self.rho)
        for path, cost in ants:
            delta = self.Q / cost
            for i in range(len(path)-1):
                pheromone[path[i]][path[i+1]] += delta




