# Utiliser une image de base contenant Go
FROM golang:1.22-alpine

# Mettre à jour et installer gcc et musl-dev
RUN apk update && apk add --no-cache gcc musl-dev

# Définir le répertoire de travail dans le conteneur
WORKDIR /api

# Copier les fichiers nécessaires dans le conteneur
COPY go.mod go.sum ./

# Télécharger les dépendances Go
RUN go mod download

# Copier le reste des fichiers de l'application dans le conteneur
COPY . .

# Compiler l'application Go
RUN go build -o go-api

# Ajouter les permissions d'exécution au binaire
RUN chmod +x go-api

# Exposer le port sur lequel l'application écoute
EXPOSE 8181

# Utiliser ENTRYPOINT pour démarrer l'application
CMD ["./go-api"]
