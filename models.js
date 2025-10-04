import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
    nombre: { type: String, required: true },
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    token: { type: String, default: null },
    role: { type: String, enum: ['admin', 'regular'], required: true, default: "regular" },

    banco: {
        entidad: { type: String },
        numeroCuenta: { type: String },
        titular: { type: String }
    },

    wallet: {
        direccion: { type: String },
        red: { type: String }
    }
});

const recargaSchema = new mongoose.Schema({
    usuarioId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    monto: { type: Number, required: true },
    BobExchangeRate: { type: Number, required: true },
    fecha: { type: Date, default: Date.now },
    walletUsuario: { type: String, required: true },
    red: { type: String, required: true },
    comprobanteUrl: { type: String, required: true },
    estado: { type: String, enum: ['pendiente', 'aprobada', 'rechazada'], default: 'pendiente' }
});

const retiroSchema = new mongoose.Schema({
    usuarioId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    monto: { type: Number, required: true },
    BobExchangeRate: { type: Number, required: true },
    fecha: { type: Date, default: Date.now },
    bancoUsuario: {
        entidad: { type: String, required: true },
        numeroCuenta: { type: String, required: true },
        titular: { type: String, required: true }
    },
    comprobanteUrl: { type: String, required: true },
    estado: { type: String, enum: ['pendiente', 'aprobado', 'rechazado'], default: 'pendiente' }
});

const infoBancosEmpresaSchema = new mongoose.Schema({
    bancos: {
        entidad: { type: String, required: true },
        numeroCuenta: { type: String, required: true },
        titular: { type: String, required: true },
        qrUrl: { type: String, required: true }
    },
    walletEmpresa: {
        direccion: { type: String, required: true },
        red: { type: String, enum: ['TRC20', 'ERC20', 'BEP20'], default: 'TRC20' },
    },
});

const infoUsdtSchema = new mongoose.Schema({
    usdtPriceSell: { type: Number, required: true },
    usdtPriceBuy: { type: Number, required: true }
});

export const InfoBancosEmpresa = mongoose.model('InfoBancosEmpresa', infoBancosEmpresaSchema);
export const Recarga = mongoose.model('Recarga', recargaSchema);
export const Retiro = mongoose.model('Retiro', retiroSchema);
export const InfoUsdt = mongoose.model('infoUsdt', infoUsdtSchema);
export const User = mongoose.model('User', userSchema);
