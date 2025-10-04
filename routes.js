import express from 'express';
import fetch from 'node-fetch';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import mongoose from "mongoose";
import { User, Recarga, Retiro, InfoBancosEmpresa, InfoUsdt } from './models.js';

const router = express.Router();

/* 📌 Crear Recarga (Compra) */
router.post('/buyusdt', async (req, res) => {
    const { usuarioId, BobExchangeRate, monto, comprobanteUrl, walletUsuario, red } = req.body;

    if (!usuarioId || !monto || !comprobanteUrl || !BobExchangeRate || !walletUsuario || !red) {
        return res.status(400).json({ error: 'Campos incompletos para la recarga' });
    }

    try {
        const usuario = await User.findById(usuarioId);
        if (!usuario) return res.status(404).json({ error: 'Usuario no encontrado' });

        const recarga = new Recarga({
            usuarioId,
            monto,
            BobExchangeRate,
            walletUsuario,
            red,
            comprobanteUrl,
        });

        await recarga.save();

        res.status(201).json({ message: 'Solicitud de recarga enviada', recarga });
    } catch (error) {
        console.error('❌ Error al registrar recarga:', error);
        res.status(500).json({ error: 'Error al registrar recarga' });
    }
});

/* 📌 Crear Retiro (Venta) */
router.post('/sellusdt', async (req, res) => {
    const { usuarioId, BobExchangeRate, monto, comprobanteUrl, bankAccount, bankName, accountHolder } = req.body;

    if (!usuarioId || !monto || !comprobanteUrl || !BobExchangeRate || !bankAccount || !bankName || !accountHolder) {
        return res.status(400).json({ error: 'Campos incompletos para el retiro' });
    }

    try {
        const usuario = await User.findById(usuarioId);
        if (!usuario) return res.status(404).json({ error: 'Usuario no encontrado' });

        const retiro = new Retiro({
            usuarioId,
            monto,
            BobExchangeRate,
            bancoUsuario: {
                entidad: bankName,
                numeroCuenta: bankAccount,
                titular: accountHolder,
            },
            comprobanteUrl,
        });

        await retiro.save();

        res.status(201).json({ message: 'Solicitud de retiro enviada', retiro });
    } catch (error) {
        console.error('❌ Error al registrar retiro:', error);
        res.status(500).json({ error: 'Error al registrar retiro' });
    }
});

router.get('/historial/:usuarioId', async (req, res) => {
    try {
        const recargas = await Recarga.find({ usuarioId: req.params.usuarioId }).sort({ fecha: -1 });
        const retiros = await Retiro.find({ usuarioId: req.params.usuarioId }).sort({ fecha: -1 });

        res.json({ recargas, retiros });
    } catch (error) {
        console.error('❌ Error al obtener historial:', error);
        res.status(500).json({ error: 'Error al obtener historial' });
    }
});

router.get("/userStats/:id", async (req, res) => {
    try {
        const userId = req.params.id;

        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ message: "ID inválido" });
        }

        const oid = new mongoose.Types.ObjectId(userId);

        const [
            comprasTotales,
            ventasTotales,
            pendientesRecargas,
            pendientesRetiros,
            comprasAgg,
            ventasAgg
        ] = await Promise.all([
            Recarga.countDocuments({ usuarioId: oid, estado: "aprobada" }),
            Retiro.countDocuments({ usuarioId: oid, estado: "aprobado" }),
            Recarga.countDocuments({ usuarioId: oid, estado: "pendiente" }),
            Retiro.countDocuments({ usuarioId: oid, estado: "pendiente" }),
            Recarga.aggregate([
                { $match: { usuarioId: oid, estado: "aprobada" } },
                { $group: { _id: null, total: { $sum: "$monto" } } }
            ]),
            Retiro.aggregate([
                { $match: { usuarioId: oid, estado: "aprobado" } },
                { $group: { _id: null, total: { $sum: "$monto" } } }
            ])
        ]);

        const dineroMovido = (comprasAgg[0]?.total || 0) + (ventasAgg[0]?.total || 0);
        const pendientes = (pendientesRecargas || 0) + (pendientesRetiros || 0);

        res.json({
            compras: comprasTotales,
            ventas: ventasTotales,
            pendientes,
            dineroMovido
        });
    } catch (err) {
        console.error("❌ Error userStats:", err);
        res.status(500).json({ message: "Error obteniendo estadísticas" });
    }
});

router.patch("/user/change-password", async (req, res) => {
    try {
        const { currentPassword, newPassword, idUser } = req.body;
        const user = await User.findById(idUser);

        if (!user) return res.status(404).json({ message: "Usuario no encontrado" });

        const validPassword = await bcrypt.compare(currentPassword, user.password);
        if (!validPassword) {
            return res.status(400).json({ message: "Contraseña actual incorrecta" });
        }

        const hashed = await bcrypt.hash(newPassword, 10);
        user.password = hashed;
        await user.save();

        res.json({ message: "Contraseña actualizada correctamente" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Error en el servidor" });
    }
});

router.get("/usdt-price", async (req, res) => {
    try {
        const info = await InfoUsdt.findOne();
        if (!info) {
            return res.status(404).json({ error: "No se encontró información de precios" });
        }
        res.json(info);
    } catch (error) {
        console.error("❌ Error al obtener precio USDT:", error);
        res.status(500).json({ error: "Error al obtener precio USDT" });
    }
});

router.post("/usdt-price", async (req, res) => {
    try {
        const { usdtPriceSell, usdtPriceBuy } = req.body;

        if (!usdtPriceSell || !usdtPriceBuy) {
            return res.status(400).json({ error: "Debes enviar usdtPriceSell y usdtPriceBuy" });
        }

        let info = await InfoUsdt.findOne();

        if (info) {
            info.usdtPriceSell = usdtPriceSell;
            info.usdtPriceBuy = usdtPriceBuy;
            await info.save();
        } else {
            info = new InfoUsdt({ usdtPriceSell, usdtPriceBuy });
            await info.save();
        }

        res.json(info);
    } catch (error) {
        console.error("❌ Error al guardar precio USDT:", error);
        res.status(500).json({ error: "Error al guardar precio USDT" });
    }
});

router.get('/empresa/bancos', async (req, res) => {
    try {
        const info = await InfoBancosEmpresa.findOne();
        res.json(info || {});
    } catch (error) {
        console.error('❌ Error al obtener info empresa:', error);
        res.status(500).json({ error: 'Error al obtener info de la empresa' });
    }
});

router.post('/empresa/bancos', async (req, res) => {
    const { bancos, walletEmpresa } = req.body;

    try {
        let info = await InfoBancosEmpresa.findOne();

        if (info) {
            if (bancos) info.bancos = bancos;
            if (walletEmpresa) info.walletEmpresa = walletEmpresa;
            await info.save();
        } else {
            info = new InfoBancosEmpresa({ bancos, walletEmpresa });
            await info.save();
        }

        res.json({ message: 'Información bancaria/Wallet actualizada', info });
    } catch (error) {
        console.error('❌ Error al guardar info empresa:', error);
        res.status(500).json({ error: 'Error al guardar info de la empresa' });
    }
});

router.get('/admin/buys', async (req, res) => {
    try {
        const recargas = await Recarga.find().populate('usuarioId');
        res.json(recargas);
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener recargas' });
    }
});

router.get('/admin/sales', async (req, res) => {
    try {
        const retiros = await Retiro.find().populate('usuarioId');
        res.json(retiros);
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener retiros' });
    }
});

router.patch('/admin/buy/:id', async (req, res) => {
    const { estado } = req.body;

    try {
        const recarga = await Recarga.findById(req.params.id);
        if (!recarga) return res.status(404).json({ error: 'Recarga no encontrada' });

        if (recarga.estado !== 'pendiente') {
            return res.status(400).json({ error: 'Esta recarga ya fue procesada.' });
        }

        const estadosValidos = ['pendiente', 'aprobada', 'rechazada'];

        if (!estadosValidos.includes(estado)) {
            return res.status(400).json({ error: 'Estado inválido' });
        }


        recarga.estado = estado;
        await recarga.save();

        res.json({ message: `Recarga ${estado} correctamente`, recarga });
    } catch (error) {
        console.error('❌ Error al actualizar recarga:', error);
        res.status(500).json({ error: 'Error al actualizar recarga' });
    }
});

router.patch('/admin/sell/:id', async (req, res) => {
    const { estado } = req.body;

    try {
        const retiro = await Retiro.findById(req.params.id);
        if (!retiro) return res.status(404).json({ error: 'Retiro no encontrado' });

        if (retiro.estado !== 'pendiente') {
            return res.status(400).json({ error: 'Este retiro ya fue procesado.' });
        }

        const estadosValidos = ['pendiente', 'aprobado', 'rechazado'];

        if (!estadosValidos.includes(estado)) {
            return res.status(400).json({ error: 'Estado inválido' });
        }

        retiro.estado = estado;
        await retiro.save();

        res.json({ message: `Retiro ${estado} correctamente`, retiro });
    } catch (error) {
        console.error('❌ Error al actualizar retiro:', error);
        res.status(500).json({ error: 'Error al actualizar retiro' });
    }
});

router.post('/register', async (req, res) => {
    const { nombre, email, password, confirmPassword } = req.body;

    if (!nombre || !email || !password || !confirmPassword) {
        return res.status(400).json({ error: 'Todos los campos obligatorios deben ser completados.' });
    }

    if (password !== confirmPassword) {
        return res.status(400).json({ error: 'Las contraseñas no coinciden.' });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(409).json({ error: 'El correo ya está registrado.' });

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({
            nombre,
            email,
            password: hashedPassword,
        });

        await user.save();
        res.status(201).json({ message: 'Usuario registrado con éxito.' });
    } catch (error) {
        console.error('Error al registrar usuario:', error);
        res.status(500).json({ error: 'Error al registrar usuario' });
    }
});

router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: 'Credenciales incorrectas' });

        const token = jwt.sign({ id: user._id }, process.env.SECRET_KEY, { expiresIn: '1d' });
        user.token = token;
        await user.save();

        res.json({ token: user.token, role: user.role });
    } catch (error) {
        res.status(500).json({ error: 'Error al iniciar sesión' });
    }
});

router.post('/logout', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token no proporcionado' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.SECRET_KEY);
        const user = await User.findById(decoded.id);
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

        user.token = null;
        await user.save();

        res.json({ message: 'Sesión cerrada exitosamente' });
    } catch (error) {
        res.status(401).json({ error: 'Token inválido o expirado' });
    }
});

router.get('/get_user_info', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token no proporcionado' });
    }

    try {
        const decoded = jwt.verify(token, process.env.SECRET_KEY);
        const user = await User.findById(decoded.id).select('-password');

        if (!user) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        res.json(user);
    } catch (error) {
        console.error('Error al verificar token o buscar usuario:', error);
        res.status(403).json({ error: 'Token inválido o expirado' });
    }
});

router.patch('/update_profile', async (req, res) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token no proporcionado' });

    try {
        const decoded = jwt.verify(token, process.env.SECRET_KEY);
        const user = await User.findById(decoded.id);
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

        const { nombre, email, banco, wallet } = req.body;

        if (nombre) user.nombre = nombre;
        if (email) user.email = email;

        if (banco) {
            if (banco.entidad) user.banco.entidad = banco.entidad;
            if (banco.numeroCuenta) user.banco.numeroCuenta = banco.numeroCuenta;
            if (banco.titular) user.banco.titular = banco.titular;
        }

        if (wallet) {
            if (wallet.direccion) user.wallet.direccion = wallet.direccion;
            if (wallet.red) user.wallet.red = wallet.red;
        }

        await user.save();

        res.json({ message: 'Perfil actualizado correctamente', user });
    } catch (err) {
        console.error('❌ Error al actualizar perfil:', err);
        res.status(500).json({ error: 'Error interno al actualizar perfil' });
    }
});

router.get('/admin/estadisticas', async (req, res) => {
    try {
        const usuariosActivos = await User.countDocuments({});

        const recargas = await Recarga.find({ estado: 'aprobada' });
        const totalComprado = recargas.reduce((sum, r) => sum + r.monto, 0);

        const retiros = await Retiro.find({ estado: 'aprobado' });
        const totalVendido = retiros.reduce((sum, r) => sum + r.monto, 0);

        const totalTransacciones = recargas.length + retiros.length;

        res.json({
            usuariosActivos,
            totalComprado,
            totalVendido,
            totalTransacciones
        });
    } catch (error) {
        console.error('❌ Error al obtener estadísticas:', error);
        res.status(500).json({ error: 'Error al obtener estadísticas' });
    }
});

export default router;
