import path from 'path';
import multer from 'multer';

const storage = multer.diskStorage({
    destination: (req: any, file: any, cb: any) => {
        cb(null, "public");
    },
    filename: (req: any, file: any, cb: any) => {
        cb(
            null,
            "image_" +
            Date.now().toString() +
            // random number between 1000 and 9999
            Math.floor(Math.random() * 8999 + 1000).toString() +
            path.extname(file.originalname)
        );
    },
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 1024 * 1024 * 2, // 2MB
    },
    fileFilter: (req: any, file: any, cb: any) => {
        const fileTypes = /jpeg|jpg|png/;
        const mimeType = fileTypes.test(file.mimetype);
        const extName = fileTypes.test(path.extname(file.originalname));
        if (mimeType && extName) {
            return cb(null, true);
        } else {
            cb(
                "Error: File upload only supports the following filetypes - " +
                fileTypes
            );
        }
    },
})

export default upload;