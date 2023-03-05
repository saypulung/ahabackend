import path from 'path';

import express, {Request, Response, NextFunction, Express } from 'express';
import * as dotenv from 'dotenv';
import { auth } from 'express-openid-connect';
import { validationResult } from 'express-validator';

dotenv.config();

import signupRequest from './requests/signup_request';

const parseErrorValidation = (errors: any) => {
    const errorMsg = new Map();
    for(var err of errors) {
        // returnError[string(err.param)] = err.msg;
        errorMsg.set(err.param, err.msg);
    }
    return Object.fromEntries(errorMsg);
};

const app: Express = express();
app.use(express.static(path.join(__dirname,'..', 'public')));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(
    auth({
        authRequired: false,
        auth0Logout: true,
        issuerBaseURL: process.env.AUTH0_DOMAIN,
        baseURL: `${process.env.APP_URL}:${process.env.PORT}`,
        clientID: process.env.AUTH0_CLIENT_ID,
        secret: process.env.APP_SECRET,
        // routes: undefined,
    })
);
app.use(express.urlencoded({ extended: false }));

app.get('/', async (req: Request, res: Response, next: NextFunction) => {
    let page = 'home';
    let user = undefined;
    if (req.oidc.isAuthenticated()) {
        page = 'dashboard';
        user = req.oidc.user;
        console.log(user);
    }
    return res.render('parts_layout', {title: 'Work at Aha', page, user});
});
app.get('/signup', async(req: Request, res: Response, next: NextFunction) => {
    return res.render('parts_layout', {title: 'Signup', page: 'signup'});
});

app.post('/signup',[ ...signupRequest, async(req: Request, res: Response, next: NextFunction) => {
    const errors = validationResult(req);
    console.log(req.body);
    console.log(errors);
    if (!errors.isEmpty()) {
        return res.status(401).json(parseErrorValidation(errors.array()));
    }
    return res.send('auk')
}]);

app.listen(
    Number(process.env.PORT),
    '0.0.0.0',
    () => console.log(`Running...${process.env.APP_URL}:${process.env.PORT}`));