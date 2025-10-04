import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';
import routes from './routes.js';
import auth from './auth.js';

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

app.use('/api', (req, res, next) => {
    if (req.path === '/login' || req.path === '/register' || req.path === "/usdt-price") {
        return next();
    }
    return auth(req, res, next);
});

app.use('/api', routes);

mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log('✅ Conectado a MongoDB');
    })
    .catch(err => console.error('❌ Error al conectar a MongoDB:', err));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
    console.log(process.env.MONGO_URI)
});
