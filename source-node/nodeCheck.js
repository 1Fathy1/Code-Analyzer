// كود ملف test.js
async function testScanner() {
    const response = await fetch("http://localhost:3000/analyze", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            lan: "node",
            vuln: "all", // جربيها "sql" أو "all" للـ Select All
            code: `
                const data = input();
                db.query(data);
                
                console.log(secret_token);
            `
        })
    });

    const result = await response.json();
    console.log("🎯 النتيجة من الـ Scanner API:\n", JSON.stringify(result, null, 2));
}

testScanner();