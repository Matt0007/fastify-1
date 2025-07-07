// Importer Fastify
const fastify = require('fastify')({ 
  logger: true 
});

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('@fastify/cors');
const oauth2 = require('fastify-oauth2');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'votre_secret_jwt_temporaire'; // À sécuriser en prod
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

// Activer CORS pour permettre les requêtes depuis React Native
fastify.register(cors, {
  origin: true,
  credentials: true
});

// Configuration OAuth2 Google
fastify.register(oauth2, {
  name: 'googleOAuth2',
  scope: ['profile', 'email'],
  credentials: {
    client: {
      id: GOOGLE_CLIENT_ID,
      secret: GOOGLE_CLIENT_SECRET
    },
    auth: {
      authorizeHost: 'https://accounts.google.com',
      authorizePath: '/o/oauth2/v2/auth',
      tokenHost: 'https://www.googleapis.com',
      tokenPath: '/oauth2/v4/token'
    }
  },
  startRedirectPath: '/auth/google',
  callbackUri: 'http://localhost:3000/auth/google/callback'
});

// Déclarer une route pour la page d'accueil
fastify.get('/', async (req, res) => {
    res.send({ message: 'Bienvenue sur mon serveur Fastify' });
});

// Route d'inscription (basée sur ton projet todolist)
fastify.post('/auth/register', async (req, res) => {
  try {
    const { name, email, password, confirmPassword } = req.body;

    // Vérifier que tous les champs sont fournis
    if (!name || !email || !password || !confirmPassword) {
      return res.status(400).send({ 
        status: "error", 
        message: "Tous les champs sont requis" 
      });
    }

    const formattedName = name.trim();
    const formattedEmail = email.trim().toLowerCase();
    // Vérifier si l'utilisateur existe déjà
    const existingUser = await prisma.user.findUnique({
      where: { email: formattedEmail },
    });

    if (existingUser) {
      return res.status(400).send({ 
        status: "error", 
        message: "Utilisateur déjà existant" 
      });
    }

    // Vérifier que les mots de passe correspondent
    if (password !== confirmPassword) {
      return res.status(400).send({ 
        status: "error", 
        message: "Les mots de passe ne correspondent pas" 
      });
    }

    // Hasher le mot de passe
    const hashedPassword = await bcrypt.hash(password, 10);

    // Créer l'utilisateur
    const user = await prisma.user.create({
      data: {
        email: formattedEmail,
        password: hashedPassword,
        name: formattedName,
      },
      select: {
        id: true,
        email: true,
        name: true,
        createdAt: true,
      },
    });

    // Générer un token JWT
    const token = jwt.sign({ 
      userId: user.id, 
      email: user.email 
    }, JWT_SECRET, { expiresIn: '7d' });

    return res.send({
      status: "success",
      message: "Utilisateur créé avec succès",
      user: user,
      token: token
    });

  } catch (error) {
    console.error('Erreur lors de l\'inscription:', error);
    return res.status(500).send({ 
      status: "error", 
      message: "Échec de la création de l'utilisateur" 
    });
  }
});

// Route de connexion (basée sur ton projet todolist)
fastify.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Vérifier que email et password sont fournis
    if (!email || !password) {
      return res.status(400).send({ 
        status: "error", 
        message: "Email et mot de passe requis" 
      });
    }

    const formattedEmail = email.trim().toLowerCase();
    // Rechercher l'utilisateur
    const user = await prisma.user.findUnique({
      where: { email: formattedEmail },
      select: {
        id: true,
        email: true,
        name: true,
        password: true,
        createdAt: true,
      },
    });

    if (!user || !user.password) {
      return res.status(400).send({ 
        status: "error", 
        message: "Utilisateur non trouvé" 
      });
    }

    // Vérifier le mot de passe
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(400).send({ 
        status: "error", 
        message: "Mot de passe incorrect" 
      });
    }

    // Générer un token JWT
    const token = jwt.sign({ 
      userId: user.id, 
      email: formattedEmail 
    }, JWT_SECRET, { expiresIn: '7d' });

    // Retourner les données utilisateur (sans le mot de passe)
    const { password: _, ...userWithoutPassword } = user;

    return res.send({
      status: "success",
      message: "Connexion réussie",
      user: userWithoutPassword,
      token: token
    });

  } catch (error) {
    console.error('Erreur lors de la connexion:', error);
    return res.status(500).send({ 
      status: "error", 
      message: "Erreur lors de la connexion" 
    });
  }
});

// Route pour vérifier un token JWT
fastify.get('/auth/verify', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).send({ 
        status: "error", 
        message: "Token d'authentification requis" 
      });
    }

    const token = authHeader.substring(7); // Enlever "Bearer "
    
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Récupérer les informations utilisateur
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: {
        id: true,
        email: true,
        name: true,
        createdAt: true,
      },
    });

    if (!user) {
      return res.status(401).send({ 
        status: "error", 
        message: "Utilisateur non trouvé" 
      });
    }

    return res.send({
      status: "success",
      message: "Token valide",
      user: user
    });

  } catch (error) {
    console.error('Erreur lors de la vérification du token:', error);
    return res.status(401).send({ 
      status: "error", 
      message: "Token invalide" 
    });
  }
});

// Route pour obtenir l'URL d'authentification Google (pour React Native)
fastify.get('/auth/google/url', async (req, res) => {
  try {
    const authorizationUri = fastify.googleOAuth2.generateAuthorizationUri({
      scope: ['profile', 'email']
    });
    
    res.send({ 
      status: 'success',
      authUrl: authorizationUri 
    });
  } catch (error) {
    console.error('Erreur lors de la génération de l\'URL Google:', error);
    res.status(500).send({ 
      status: 'error',
      message: 'Erreur lors de la génération de l\'URL d\'authentification' 
    });
  }
});

console.log('HOST:', process.env.HOST);

// N'APPELLE PAS start() AUTOMATIQUEMENT EN SERVERLESS
if (require.main === module) {
  // Lancement local classique
  const start = async () => {
    try {
      await fastify.listen({ port: 3000, host: '::' });
      console.log('Serveur démarré sur http://0.0.0.0:3000');
    } catch (err) {
      fastify.log.error(err);
      process.exit(1);
    }
  };
  start();
}

module.exports = fastify;
