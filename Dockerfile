FROM node:16-alpine

WORKDIR /app

COPY package*.json ./

COPY . .

RUN npm install

RUN npm install -g nodemon && npm install -g ts-node && npm install -g typescript

RUN npm run build

EXPOSE 4000

CMD ["npm", "run", "start"]
