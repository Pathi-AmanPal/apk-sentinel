async function checkJob(jobId) {
  const url = `https://apk-sentinel.vercel.app/api/status/${jobId}`;
  console.log('Polling status for job:', jobId);
  
  for (let i = 0; i < 20; i++) {
    const res = await fetch(url);
    const data = await res.json();
    console.log(`Poll ${i+1}:`, JSON.stringify(data, null, 2));
    if (data.status === 'completed' || data.status === 'failed') {
      if (data.status === 'completed') {
        const reportRes = await fetch(`https://apk-sentinel.vercel.app/api/report/${jobId}?format=json`);
        const reportData = await reportRes.json();
        console.log('Final Report:', JSON.stringify(reportData, null, 2));
      }
      return;
    }
    await new Promise(r => setTimeout(r, 2000));
  }
  console.log('Polling timed out.');
}

checkJob('a64e4028-d716-4ab1-b369-4e8bb36da275');
