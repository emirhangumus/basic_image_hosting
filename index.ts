import type { Express, Request, Response } from 'express';
import express from 'express';
import dotenv from 'dotenv';
import upload from './upload/upload';
import path from 'path';
import { encode } from 'blurhash';
import Jimp from 'jimp';
import cors from 'cors';
import corsOptions from './middlewares/cors';

dotenv.config();

const app: Express = express();
const port = process.env.PORT;

app.use(express.json({ limit: '20mb' }));

app.use(express.urlencoded({ extended: true, limit: '20mb' }));

app.use(cors(corsOptions));

app.use('/api/v1/public', express.static(path.join(process.cwd(), 'public')));

app.post('/api/v1/upload', upload.single('image'), async (req: Request, res: Response) => {
    try {
        if (!req.file) {
            throw new Error('Image not found - 0');
        }

        const filePath = req.file.path.replace(/\\\\/g, "\\");

        if (!filePath) {
            throw new Error('Image not found - 1');
        }

        // create blurhash
        const image = await Jimp.read(filePath);
        const Uint8ClampedArray_ = new Uint8ClampedArray(image.bitmap.data);
        // use `encode`
        const blurhash = encode(Uint8ClampedArray_, image.bitmap.width, image.bitmap.height, 4, 3);

        return res.status(200).json({
            success: true,
            data: {
                path: filePath,
                blurhash: blurhash,
            },
        });
    }
    catch (error: any) {
        res.status(400).json({
            success: false,
            error: error.message,
        });
    }
});

app.listen(port, () => {
    console.log(`⚡️[server]: Server is running at http://localhost:${port}`);
});