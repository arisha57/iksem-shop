const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const app = express();
const PORT = 3000;
const db = require('./database.js');

const JWT_SECRET = 'shh-secret-key-2024';

// Папка для фото
const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Настройка multer
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|webp/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        if (mimetype && extname) {
            cb(null, true);
        } else {
            cb(new Error('Только изображения'));
        }
    }
});

app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));

// ============ ВСПОМОГАТЕЛЬНЫЕ ============
function getUserFromToken(req) {
    const token = req.cookies.token;
    if (!token) return null;
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return null;
    }
}

function requireAdmin(req, res, next) {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Не авторизован' });
    try {
        const user = jwt.verify(token, JWT_SECRET);
        if (!user.is_admin) return res.status(403).json({ error: 'Доступ запрещён' });
        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Недействительный токен' });
    }
}

// ============ АВТОРИЗАЦИЯ ============
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email и пароль обязательны' });
    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
        if (user) return res.status(400).json({ error: 'Пользователь уже существует' });
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run("INSERT INTO users (email, password, is_admin) VALUES (?, ?, 0)", [email, hashedPassword], function(err) {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            const token = jwt.sign({ id: this.lastID, email, is_admin: 0 }, JWT_SECRET, { expiresIn: '7d' });
            res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
            res.json({ success: true, message: 'Регистрация успешна' });
        });
    });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email и пароль обязательны' });
    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'Неверный email или пароль' });
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Неверный email или пароль' });
        const token = jwt.sign({ id: user.id, email: user.email, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '7d' });
        res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
        res.json({ success: true, message: 'Вход выполнен', is_admin: user.is_admin === 1 });
    });
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ success: true, message: 'Выход выполнен' });
});

app.get('/api/me', (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.json({ user: null });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        res.json({ user: { id: decoded.id, email: decoded.email, is_admin: decoded.is_admin } });
    } catch (error) {
        res.clearCookie('token');
        res.json({ user: null });
    }
});

// ============ ТОВАРЫ ============
app.get('/api/products', (req, res) => {
    db.all("SELECT * FROM products ORDER BY id DESC", (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.get('/api/products/:id', (req, res) => {
    db.get("SELECT * FROM products WHERE id = ?", [req.params.id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(row);
    });
});

app.get('/api/products/:id/images', (req, res) => {
    db.all("SELECT * FROM product_images WHERE product_id = ? ORDER BY sort_order", [req.params.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// ============ АДМИН ТОВАРЫ ============
app.post('/api/admin/products', requireAdmin, upload.array('images', 10), (req, res) => {
    const { name, description, price, size, color, composition } = req.body;
    if (!name || !price) return res.status(400).json({ error: 'Название и цена обязательны' });
    db.run(
        `INSERT INTO products (name, description, price, size, color, composition) VALUES (?, ?, ?, ?, ?, ?)`,
        [name, description || '', price, size || '', color || '', composition || ''],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            const productId = this.lastID;
            if (req.files && req.files.length > 0) {
                req.files.forEach((file, index) => {
                    db.run("INSERT INTO product_images (product_id, image_url, sort_order) VALUES (?, ?, ?)",
                        [productId, `/uploads/${file.filename}`, index]);
                });
            }
            res.json({ success: true, message: 'Товар добавлен', product: { id: productId } });
        }
    );
});

app.put('/api/admin/products/:id', requireAdmin, (req, res) => {
    const { name, description, price, size, color, composition } = req.body;
    db.run(
        `UPDATE products SET name = ?, description = ?, price = ?, size = ?, color = ?, composition = ? WHERE id = ?`,
        [name, description, price, size, color, composition, req.params.id],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, message: 'Товар обновлён' });
        }
    );
});

app.delete('/api/admin/products/:id', requireAdmin, (req, res) => {
    const id = req.params.id;
    
    // Сначала получаем все фото товара
    db.all("SELECT image_url FROM product_images WHERE product_id = ?", [id], (err, images) => {
        if (err) {
            console.error('Ошибка получения фото:', err);
            return res.status(500).json({ error: err.message });
        }
        
        // Удаляем файлы фото
        if (images && images.length > 0) {
            images.forEach(img => {
                if (img.image_url) {
                    const filePath = path.join(__dirname, 'public', img.image_url);
                    try {
                        if (fs.existsSync(filePath)) {
                            fs.unlinkSync(filePath);
                        }
                    } catch (e) {
                        console.error('Ошибка удаления файла:', e);
                    }
                }
            });
        }
        
        // Удаляем записи из product_images
        db.run("DELETE FROM product_images WHERE product_id = ?", [id], (err) => {
            if (err) {
                console.error('Ошибка удаления фото из БД:', err);
                return res.status(500).json({ error: err.message });
            }
            
            // Удаляем товар из корзин
            db.run("DELETE FROM cart WHERE product_id = ?", [id], (err) => {
                if (err) {
                    console.error('Ошибка удаления из корзин:', err);
                    return res.status(500).json({ error: err.message });
                }
                
                // Удаляем сам товар
                db.run("DELETE FROM products WHERE id = ?", [id], function(err) {
                    if (err) {
                        console.error('Ошибка удаления товара:', err);
                        return res.status(500).json({ error: err.message });
                    }
                    if (this.changes === 0) {
                        return res.status(404).json({ error: 'Товар не найден' });
                    }
                    res.json({ success: true, message: 'Товар удалён' });
                });
            });
        });
    });
});

app.post('/api/admin/products/:id/images', requireAdmin, upload.single('image'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Фото не загружено' });
    db.run("INSERT INTO product_images (product_id, image_url) VALUES (?, ?)",
        [req.params.id, `/uploads/${req.file.filename}`],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, message: 'Фото добавлено' });
        }
    );
});

app.delete('/api/admin/products/images/:image_id', requireAdmin, (req, res) => {
    db.get("SELECT image_url FROM product_images WHERE id = ?", [req.params.image_id], (err, image) => {
        if (!image) return res.status(404).json({ error: 'Фото не найдено' });
        const filePath = path.join(__dirname, 'public', image.image_url);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        db.run("DELETE FROM product_images WHERE id = ?", [req.params.image_id], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, message: 'Фото удалено' });
        });
    });
});

// ============ КОРЗИНА ============
app.get('/api/cart', (req, res) => {
    const user = getUserFromToken(req);
    if (!user) return res.status(401).json({ error: 'Необходимо войти' });
    db.all(`
        SELECT c.id as cart_id, c.product_id, c.quantity, c.size, c.color,
               p.name, p.price
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = ?
    `, [user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        let total = 0;
        const items = rows.map(item => {
            const subtotal = item.price * item.quantity;
            total += subtotal;
            return { ...item, subtotal };
        });
        res.json({ items, total });
    });
});

app.post('/api/cart/add', (req, res) => {
    const user = getUserFromToken(req);
    if (!user) return res.status(401).json({ error: 'Необходимо войти' });
    const { product_id, quantity = 1, size = '', color = '' } = req.body;
    if (!product_id) return res.status(400).json({ error: 'ID товара обязателен' });
    db.get(
        "SELECT * FROM cart WHERE user_id = ? AND product_id = ? AND size = ? AND color = ?",
        [user.id, product_id, size, color],
        (err, existing) => {
            if (err) return res.status(500).json({ error: err.message });
            if (existing) {
                db.run("UPDATE cart SET quantity = quantity + ? WHERE id = ?", [quantity, existing.id], function(err) {
                    if (err) return res.status(500).json({ error: err.message });
                    res.json({ success: true, message: 'Количество обновлено' });
                });
            } else {
                db.run("INSERT INTO cart (user_id, product_id, quantity, size, color) VALUES (?, ?, ?, ?, ?)",
                    [user.id, product_id, quantity, size, color], function(err) {
                        if (err) return res.status(500).json({ error: err.message });
                        res.json({ success: true, message: 'Товар добавлен в корзину' });
                    }
                );
            }
        }
    );
});

app.put('/api/cart/update', (req, res) => {
    const user = getUserFromToken(req);
    if (!user) return res.status(401).json({ error: 'Необходимо войти' });
    const { cart_id, quantity } = req.body;
    if (quantity < 1) {
        db.run("DELETE FROM cart WHERE id = ? AND user_id = ?", [cart_id, user.id]);
        res.json({ success: true });
    } else {
        db.run("UPDATE cart SET quantity = ? WHERE id = ? AND user_id = ?", [quantity, cart_id, user.id]);
        res.json({ success: true });
    }
});

app.delete('/api/cart/remove/:cart_id', (req, res) => {
    const user = getUserFromToken(req);
    if (!user) return res.status(401).json({ error: 'Необходимо войти' });
    db.run("DELETE FROM cart WHERE id = ? AND user_id = ?", [req.params.cart_id, user.id]);
    res.json({ success: true });
});

// ============ ЗАКАЗЫ ============
app.post('/api/orders', async (req, res) => {
    const user = getUserFromToken(req);
    if (!user) return res.status(401).json({ error: 'Необходимо войти' });
    
    const { address, phone, social, comment } = req.body;
    if (!address || !phone || !social) return res.status(400).json({ error: 'Заполните все поля' });
    
    db.all(`
        SELECT c.product_id, c.quantity, c.size, c.color, p.name, p.price
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = ?
    `, [user.id], async (err, cartItems) => {
        if (err) return res.status(500).json({ error: err.message });
        if (cartItems.length === 0) return res.status(400).json({ error: 'Корзина пуста' });
        
        const totalAmount = cartItems.reduce((sum, item) => sum + (item.price * item.quantity), 0);
        const orderNumber = 'SHH-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
        
        db.run(`
            INSERT INTO orders (order_number, user_id, user_email, total_amount, address, phone, social, comment, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [orderNumber, user.id, user.email, totalAmount, address, phone, social, comment || '', 'новый'],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            
            const orderId = this.lastID;
            let inserted = 0;
            const totalItems = cartItems.length;
            
            if (totalItems === 0) {
                db.run("DELETE FROM cart WHERE user_id = ?", [user.id]);
                return res.json({ success: true, message: 'Заказ оформлен', order: { number: orderNumber, total: totalAmount } });
            }
            
            cartItems.forEach(item => {
                db.run(`
                    INSERT INTO order_items (order_id, product_id, product_name, price, quantity, size, color)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                `, [orderId, item.product_id, item.name, item.price, item.quantity, item.size || '', item.color || ''],
                function(err) {
                    if (err) {
                        console.error('Ошибка вставки товара:', err);
                    }
                    inserted++;
                    
                    if (inserted === totalItems) {
                        db.run("DELETE FROM cart WHERE user_id = ?", [user.id]);
                        res.json({ 
                            success: true, 
                            message: 'Заказ оформлен', 
                            order: { number: orderNumber, total: totalAmount, items: totalItems }
                        });
                    }
                });
            });
        });
    });
});

app.get('/api/orders', (req, res) => {
    const user = getUserFromToken(req);
    if (!user) return res.status(401).json({ error: 'Необходимо войти' });
    db.all("SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC", [user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.get('/api/orders/:id', (req, res) => {
    const user = getUserFromToken(req);
    if (!user) {
        return res.status(401).json({ error: 'Необходимо войти' });
    }
    
    const orderId = req.params.id;
    console.log(`Запрос деталей заказа ID: ${orderId} для пользователя ${user.id}`);
    
    // Сначала проверяем, существует ли заказ
    db.get("SELECT * FROM orders WHERE id = ?", [orderId], (err, order) => {
        if (err) {
            console.error('Ошибка БД:', err);
            return res.status(500).json({ error: err.message });
        }
        
        if (!order) {
            console.log(`Заказ ${orderId} не найден`);
            return res.status(404).json({ error: 'Заказ не найден' });
        }
        
        // Проверяем, принадлежит ли заказ этому пользователю
        if (order.user_id !== user.id) {
            console.log(`Заказ ${orderId} принадлежит другому пользователю`);
            return res.status(403).json({ error: 'Доступ запрещён' });
        }
        
        // Загружаем товары заказа
        db.all("SELECT * FROM order_items WHERE order_id = ?", [orderId], (err, items) => {
            if (err) {
                console.error('Ошибка загрузки товаров:', err);
                return res.status(500).json({ error: err.message });
            }
            
            console.log(`Найдено ${items.length} товаров в заказе ${orderId}`);
            res.json({ ...order, items });
        });
    });
});

app.get('/api/admin/orders', requireAdmin, (req, res) => {
    db.all(`
        SELECT o.*, u.email as user_email 
        FROM orders o 
        LEFT JOIN users u ON o.user_id = u.id 
        ORDER BY o.created_at DESC
    `, (err, rows) => {
        if (err) {
            console.error('Ошибка загрузки заказов:', err);
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});

app.put('/api/admin/orders/:id/status', requireAdmin, (req, res) => {
    const { status } = req.body;
    const validStatuses = ['новый', 'обработка', 'отправлен', 'доставлен', 'отменён'];
    if (!validStatuses.includes(status)) return res.status(400).json({ error: 'Неверный статус' });
    db.run("UPDATE orders SET status = ? WHERE id = ?", [status, req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// Для админа: получить товары заказа
app.get('/api/admin/orders/:id/items', requireAdmin, (req, res) => {
    const orderId = req.params.id;
    db.all("SELECT * FROM order_items WHERE order_id = ?", [orderId], (err, items) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(items);
    });
});

app.listen(PORT, () => {
    console.log(`Сервер shh! работает: http://localhost:${PORT}`);
    console.log(`Админ: monastyrskaya2704@gmail.com / iksem.xm2704`);
});
