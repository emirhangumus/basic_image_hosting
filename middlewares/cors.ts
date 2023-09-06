import { CorsOptions } from "cors";

const allowedOrigins: string[] = [
    "http://localhost:3000",
];

const corsOptions: CorsOptions = {
    credentials: true,
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        }
        else {
            callback(new Error("Not allowed by CORS"));
        }
    },
    optionsSuccessStatus: 200,
};

export default corsOptions;
