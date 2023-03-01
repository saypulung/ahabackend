import express, {Request, Response, NextFunction, Express } from 'express';
import * as dotenv from 'dotenv';
import { auth } from 'express-openid-connect';

dotenv.config();

const app: Express = express();

app.get('/', (req: Request, res: Response, next: NextFunction) => {
    res.send('Wedos prucul');
});

app.listen(3000, () => console.log(`Running...${process.env.APP_URL}`));