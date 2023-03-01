import express, {Request, Response, NextFunction, Express } from 'express';
import * as dotenv from 'dotenv';
import { auth } from 'express-openid-connect';

dotenv.config();

const app: Express = express();

app.use(
    auth({
        authRequired: false,
        auth0Logout: true,
        issuerBaseURL: process.env.AUTH0_DOMAIN,
        baseURL: `${process.env.APP_URL}:${process.env.PORT}`,
        clientID: process.env.AUTH0_CLIENT_ID,
        secret: process.env.APP_SECRET,
    })
);

app.get('/', (req: Request, res: Response, next: NextFunction) => {
    res.send(`Wedos prucul ${req.oidc.isAuthenticated()}`);
});

app.listen(process.env.PORT, () => console.log(`Running...${process.env.APP_URL}:${process.env.PORT}`));