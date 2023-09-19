import JWT from "jsonwebtoken";
import type { Request, Response, NextFunction } from "express";

export const auth = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const authorizationHeader = req.headers.authorization;
        if (!authorizationHeader) {
            return res.status(401).json({
                success: false,
                message: "No authorization header found",
            });
        }
        const key = process.env.JWT_KEY;
        if (!key) {
            return res.status(401).json({
                success: false,
                message: "No key provided",
            });
        }
        const token = authorizationHeader.split(" ")[1];
        const decoded = JWT.verify(token, key);
        if (!decoded) {
            return res.status(401).json({
                success: false,
                message: "Invalid token",
            });
        }
        next();
    }
    catch (error) {
        return res.status(401).json({
            success: false,
            message: "Auth failed",
        });
    }
};