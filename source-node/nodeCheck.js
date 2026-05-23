const requestData = {
  lan: "javascript",               
  vuln: "all",                     
  code: "const data = req.query.id; db.query(data);" 
};

fetch("http://localhost:3000/analyze", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify(requestData)
})
// 👇 التعديل هنا: بنستقبله كنص صريح (Text) مش JSON
.then(response => response.text()) 
.then(findingsText => {
  // هنا الـ findingsText هيرجع عبارة عن String متفرمت بالـ Single Quotes بالظبط
  console.log("check result: \n", findingsText);
  
  // لما تيجي تعرضيه في الفرونت إند جوه كارت أو الـ UI 
  // هتحطيه جوه تاج <pre><code> عشان يحافظ على المسافات والأسطر
  // مثلاً لو بتستخدمي React أو JS عادية:
  // myDOMElement.innerText = findingsText;
})
.catch(error => console.error("Error:", error));