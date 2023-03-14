import { body } from "express-validator";

const profileRequest = [
    body('given_name', 'empty name')
        .trim()
        .isLength({ min: 3 })
        .withMessage('Name at least 3 characters')
        .isLength({ max: 30 })
        .withMessage('max 30')
        .escape(),
    body('family_name', 'empty family name')
        .optional({ checkFalsy: true })
        .trim()
        .isLength({ max: 30 })
        .withMessage('max 30')
        .escape(),
    body('phone').optional({ checkFalsy: true })
        .custom((value) => {
            if (value.match(/[0-9() +-]/g).length == value.length) {
                return true;
            }
            else {
                return false;
            }
        })
        .withMessage('please provide a valid number phone'),
    body('birthday').optional({checkFalsy: true})
        .custom((value) => {
            if (value.match(/^\d{4}-\d{2}-\d{2}$/gs)) {
                return true;
            } else {
                return false;
            }
        }).withMessage('please provide valid date. format: yyyy-mm-dd'),
    body('bio').trim()
        .isLength({max: 190})
        .withMessage('please write less than or equals 190 characters')
        .escape(),
];
export default profileRequest;