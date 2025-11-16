import express from "express";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { randomUUID } from 'crypto';
import { createClient } from "redis";
import { promisify } from "util";

const app = express();
// CONNECT EXPRESS TO REDIS
// Create Redis client
export const redisClient = createClient({
  url: 'redis://localhost:6379'
  // If Redis runs on a remote server or needs a password
  // url: 'redis://:yourpassword@hostname:6379'
});

// exit on failure
redisClient.on('error', (err) => {
    console.error('Redis Client Error', err);
    process.exit(1); // Exit app on failure
});

// Connect to Redis
await redisClient.connect();

app.use(cookieParser())
const port = process.env.PORT || 3000;


// JWT CONFIG
const access_key = process.env.ACCESS_KEY || 'your-secret-key';
const refresh_key = process.env.REFRESH_KEY || 'your-refresh-key';

const access_options = {
    expiresIn: '10s',
    // issuer: 'my-app',
    // subject: 'user-auth',
    // audience: 'my-app-users',
    algorithm: 'HS256',
    // jwtid: 'unique-id-001'
}

const refresh_options = {
    expiresIn: '5m',
    // issuer: 'my-app',
    // subject: 'user-auth',
    // audience: 'my-app-users',
    algorithm: 'HS256',
}

const getAccessToken=(payload)=>{
    const token = jwt.sign(payload, access_key, {...access_options, jwtid:randomUUID()});    
    return token
}

const getRefreshToken =(payload)=>{
    const token = jwt.sign(payload, refresh_key, {...refresh_options, jwtid:randomUUID()});    
    return token
}


app.get('/', (req, res) => {
    res.json({message:"Welcome to the Express-JWT"})
});

app.get('/login', async (req,res)=>{
    const payload = {
        username: "Jane Doe",
        role: "admin"
    };

    const accessToken = getAccessToken(payload);    
    const refreshToken = getRefreshToken(payload);

    // Store refresh token in Redis with 7 days expiry
    await redisClient.set(
        `refresh:${payload.username}`, //Redis key
        refreshToken, //value stored in Redis under that key
        {EX: 7 * 24 * 60 * 60,} //sets the expiration time for the key, After 7 days, the refresh token will automatically be removed from Redis.
    );
    
    // Store refresh-token in HTTP-only cookie
    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: false,         // set to true in production (HTTPS)
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });
    res.json({token:accessToken})
})

app.get('/refresh', async(req, res) => {
  const token = req.cookies?.refreshToken;
  if (!token) {
    return res.status(401).json({ message: 'Refresh token missing' });
  }
  try {
    const verifyAsync = promisify(jwt.verify);
    const payload = await verifyAsync(token, refresh_key, refresh_options);
    // Check if refresh token exists in Redis for this user
    const storedToken = await redisClient.get(`refresh:${payload.username}`);
    if (!storedToken) {
        // Token not found or expired in Redis
        return res.status(403).json({ message: 'Refresh token expired or invalid' });
    }

    // comparing token
    if (token !== storedToken) {
        return res.status(403).json({ message: 'Token mismatch' });
    }

    // Delete/Revoke the old refresh token from Redis
    await redisClient.del(`refresh:${payload.username}`);

    // Refresh token is valid - issue new refresh token and new access token    
    const refreshToken = getRefreshToken({username:payload.username, role:payload.role})
    const accessToken = getAccessToken({username:payload.username, role:payload.role})

    // Store new refresh token in Redis
    await redisClient.set(
        `refresh:${payload.username}`, //Redis key
        refreshToken, //value stored in Redis under that key
        {EX: 7 * 24 * 60 * 60,} //sets the expiration time for the key, After 7 days, the refresh token will automatically be removed from Redis.
    );
    // Store refresh-token in HTTP-only cookie
    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: false,         // set to true in production (HTTPS)
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });
    res.json({token:accessToken});
  } catch (error) {
    return res.status(403).json({ message: 'Invalid or expired refresh token' });
  }
});

app.post('/revoke', async (req,res)=>{
    const token = req.cookies?.refreshToken;
    if (!token) {
        return res.status(400).json({ message: 'Refresh token is required' });
    }
    
    try {
        const verifyAsync = promisify(jwt.verify);
        const payload = await verifyAsync(token, refresh_key, refresh_options);
        await redisClient.del(`refresh:${payload.username}`);
        res.status(200).json({ message: 'Refresh token revoked successfully' });
    } catch (error) {
        return res.status(403).json({ message: 'Invalid or expired refresh token' });
    }
})

app.get('/protected', async (req,res)=>{
    const token = req.headers.authorization?.split(' ')[1]; // Extract token from "Bearer <token>"
    if (!token) {
        return res.status(401).json({ message: "Token missing" });
    }

    jwt.verify(token, access_key, access_options, (err, payload) => {
        if (err) {
            console.log(err)
            return res.status(401).json({ message: "Unauthorized" });
        }
        // Token is valid, payload contains the user data
        res.send(payload);
    });
})

app.get('/logout', async (req, res)=>{
  const token = req.cookies?.refreshToken;
  if (!token) {
    return res.status(400).json({ message: 'No refresh token provided' });
  }
  try {
    const verifyAsync = promisify(jwt.verify);
    const payload = await verifyAsync(token, refresh_key, refresh_options);

    // Remove the token from Redis
    await redisClient.del(`refresh:${payload.username}`);

    // Clear cookie on client
    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: false,   // true in production
      sameSite: 'strict',
    });
    return res.status(200).json({ message: 'Logged out successfully' });
  } catch (err) {
    return res.status(403).json({ message: 'Invalid refresh token' });
  }
})

// app.listen(port, () => {
//   console.log(`Server listening at http://localhost:${port}`);
// });

export default app
