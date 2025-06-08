// server.js
const express    = require('express');
const session    = require('express-session');
const bcrypt     = require('bcryptjs');
const morgan     = require('morgan');
const fs         = require('fs');
const bodyParser = require('body-parser');
const mongoose   = require('mongoose');
const jwt        = require('jsonwebtoken');
const multer     = require('multer');
const PDFDocument= require('pdfkit');
const bwipjs     = require('bwip-js');
const path       = require('path');

const JWT_SECRET = process.env.JWT_SECRET || 'replace_with_env_secret';
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const CERT_DIR   = path.join(__dirname, 'public', 'certificates');
const PORT       = process.env.PORT || 3000;

// Ensure directories exist
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!fs.existsSync(CERT_DIR)) fs.mkdirSync(CERT_DIR, { recursive: true });

// File upload config
const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename:    (req, file, cb) => cb(null, file.originalname)
});
const upload = multer({ storage });

const app = express();

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/diab_reg', { useNewUrlParser:true, useUnifiedTopology:true })
  .then(()=>console.log('✅ MongoDB connected'))
  .catch(e=>console.error('❌ MongoDB error:', e));

// Define schemas and models
const companySchema = new mongoose.Schema({ matichen_broj:{ type:String, unique:true }, name:String, email:String, passwordHash:String });
const applicationSchema = new mongoose.Schema({
  company:    { type:mongoose.Schema.Types.ObjectId, ref:'Company' },
  contact:    String,
  email:      String,
  product:    String,
  docs:       [String],
  status:     { type:String, default:'Pending' },
  cert_number:String,
  completedBy:String
}, { timestamps:true });
const logSchema = new mongoose.Schema({ user:String, action:String, itemId:String, timestamp:{ type:Date, default:Date.now } });

mongoose.model('Company', companySchema);
mongoose.model('Application', applicationSchema);
mongoose.model('Log', logSchema);

// Middleware setup
app.use(morgan('combined', { stream: fs.createWriteStream('access.log', { flags:'a' }) }));
app.use(session({ secret:'diabreg-session-key', resave:false, saveUninitialized:false }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended:true }));
app.use('/uploads',    express.static(UPLOAD_DIR));
app.use('/certificates',express.static(CERT_DIR));
app.use(express.static(path.join(__dirname,'public')));

// Audit logging
const Log = mongoose.model('Log');
app.use(async (req, res, next) => {
  if (req.session?.user) {
    await Log.create({ user:req.session.user.username, action:`${req.method} ${req.originalUrl}`, itemId:req.params.id||'' });
  }
  next();
});

// Authentication middleware
function requireAdmin(req, res, next) {
  if (!req.session?.user) return res.redirect('/login');
  next();
}
function authGuard(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error:'Missing token' });
  try {
    req.companyId = jwt.verify(auth.slice(7), JWT_SECRET).id;
    next();
  } catch {
    return res.status(401).json({ error:'Invalid token' });
  }
}

// User login/logout routes
app.get('/login', (req, res) => res.sendFile(path.join(__dirname,'public','login.html')));
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const users = require('./config/users');
  const user = users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).send('Невалиден корисник/лозинка');
  }
  req.session.user = { username };
  res.redirect('/admin');
});
app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

// Certificate generation and download
const router = express.Router();
const Application = mongoose.model('Application');

async function generateCertificate(req, res) {
  try {
    const param = req.params.id;
    let query;
    if (mongoose.Types.ObjectId.isValid(param)) query = { _id: param };
    else query = { cert_number: param };

    const appDoc = await Application.findOne(query).populate('company','name');
    if (!appDoc) return res.status(404).json({ error:'Не постои апликација/сертификат' });

    const certNum = appDoc.cert_number || `DIAB-${Date.now()}`;
    if (!appDoc.cert_number) {
      appDoc.cert_number = certNum;
      appDoc.status      = 'Completed';
      appDoc.completedBy = req.session.user.username;
      await appDoc.save();
    }

    const issueDate = new Date();
    const validTo   = new Date(issueDate);
    validTo.setFullYear(validTo.getFullYear()+1);

    const pdfPath = path.join(CERT_DIR, `${certNum}.pdf`);
    const doc = new PDFDocument();
    const stream = fs.createWriteStream(pdfPath);
    doc.pipe(stream);

    doc.fontSize(25).text('DIAB-REG CERTIFICATE', { align:'center' });
    doc.moveDown();
    doc.fontSize(16).text(`Certified Company: ${appDoc.company.name}`);
    doc.text(`Product: ${appDoc.product}`);
    doc.text(`Issued to: ${appDoc.contact}`);
    doc.text(`Date: ${issueDate.toLocaleDateString()}`);
    doc.text(`Valid to: ${validTo.toLocaleDateString()}`);
    doc.text(`Certificate No: ${certNum}`);

    // Generate QR code pointing to confirmation URL
    const confirmUrl = `${req.protocol}://${req.get('host')}/certificate/confirm/${certNum}`;
    const qrPng = await bwipjs.toBuffer({ bcid:'qrcode', text:confirmUrl, scale:5, includetext:false });
    doc.image(qrPng, doc.page.width - 150, 50, { width: 100 });

    doc.end();
    stream.on('finish', () => {
      res.download(pdfPath, err => { if (!err) fs.unlinkSync(pdfPath); });
    });

  } catch (e) {
    console.error('Грешка при генерирање на сертификат:', e);
    res.status(500).json({ error:'Грешка при издавање сертификат' });
  }
}

// Confirmation page route
app.get('/certificate/confirm/:certNum', async (req, res) => {
  try {
    const certNum = req.params.certNum;
    const appDoc = await Application.findOne({ cert_number: certNum });
    if (!appDoc) return res.status(404).send('<h1>Сертификат не е пронајден</h1>');
    // Render simple approved page
    res.send(`
      <!DOCTYPE html>
      <html>
      <head><meta charset="utf-8"><title>Одобрено</title></head>
      <body style="display:flex;justify-content:center;align-items:center;height:100vh;">
        <div style="text-align:center;">
          <h1 style="color:green;font-size:48px;">Одобрено</h1>
          <p>Certificate No: ${certNum}</p>
        </div>
      </body>
      </html>
    `);
  } catch (e) {
    console.error('Грешка на потврда:', e);
    res.status(500).send('<h1>Внатрешна грешка</h1>');
  }
});

// Mount certificate routes
app.use('/api/certificate', requireAdmin, router);
app.get('/api/certificate/public/pdf/:id', authGuard, generateCertificate);

// Admin UI & API
app.get('/admin', requireAdmin, (req, res) => res.sendFile(path.join(__dirname,'public','admin.html')));
app.use('/api/admin', requireAdmin, require('./routes/admin'));
app.get('/api/admin/applications', requireAdmin, async (req, res) => {
  res.json(await Application.find().populate('company'));
});
app.get('/api/admin/logs', requireAdmin, async (req, res) => {
  const Log = mongoose.model('Log');
  res.json(await Log.find().sort({ timestamp:-1 }).limit(200));
});

// Public JWT-based API
app.post('/api/auth/register', async (req, res) => {
  const { matichen_broj, name, email, password } = req.body;
  if (!matichen_broj||!name||!email||!password) return res.status(400).json({ success:false, error:'Missing fields' });
  try {
    const hash = bcrypt.hashSync(password, 10);
    await mongoose.model('Company').create({ matichen_broj, name, email, passwordHash:hash });
    res.json({ success:true });
  } catch (e) {
    res.status(400).json({ success:false, error:e.message });
  }
});
app.post('/api/auth/login', async (req, res) => {
  const { matichen_broj, password } = req.body;
  const comp = await mongoose.model('Company').findOne({ matichen_broj });
  if (!comp||!bcrypt.compareSync(password, comp.passwordHash)) return res.status(401).json({ error:'Invalid credentials' });
  const token = jwt.sign({ id:comp._id }, JWT_SECRET, { expiresIn:'8h' });
  res.json({ token });
});

// Application endpoints
app.post('/api/apply',         authGuard, upload.array('docs'), async (req, res) => {
  const { contact, email, product } = req.body;
  const files = (req.files||[]).map(f=>f.originalname);
  const doc = await Application.create({ company:req.companyId, contact, email, product, docs:files });
  res.json({ id:doc._id });
});
app.get('/api/status/:id',      async (req, res) => {
  const doc = await Application.findById(req.params.id).populate('company');
  if (!doc) return res.json({ found:false });
  res.json({ found:true, application:{ status:doc.status, company:doc.company.name, cert_number:doc.cert_number||null } });
});
app.get('/api/my/applications', authGuard, async (req, res) => {
  res.json(await Application.find({ company:req.companyId }).sort({ createdAt:-1 }).populate('company').exec());
});

// Start server
app.listen(PORT, () => console.log(`🚀 Listening on http://localhost:${PORT}`));
