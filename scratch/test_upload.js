import fs from 'fs';
import path from 'path';

async function testUpload() {
  const url = 'https://apk-sentinel.vercel.app/api/analyze';
  
  // Read the dummy apk file
  const filePath = path.join(process.cwd(), 'test.apk');
  const fileBuffer = fs.readFileSync(filePath);
  
  // Construct multi-part form data manually
  const boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW';
  const header = `${boundary}\r\nContent-Disposition: form-data; name="apk"; filename="test.apk"\r\nContent-Type: application/vnd.android.package-archive\r\n\r\n`;
  const footer = `\r\n${boundary}--\r\n`;
  
  const body = Buffer.concat([
    Buffer.from(header, 'utf-8'),
    fileBuffer,
    Buffer.from(footer, 'utf-8')
  ]);
  
  console.log('Sending request to', url);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': `multipart/form-data; boundary=${boundary.slice(2)}`,
        'Content-Length': body.length.toString()
      },
      body: body
    });
    
    console.log('Status:', res.status);
    const text = await res.text();
    console.log('Response (first 500 chars):', text.slice(0, 500));
  } catch (err) {
    console.error('Error:', err);
  }
}

testUpload();
