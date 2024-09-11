import React, { useEffect, useState } from 'react';
import './App.css';
import jsPDF from 'jspdf';
import 'jspdf-autotable';

function App() {
  const [showButtons, setShowButtons] = useState(false);
  const [showUploadSection, setShowUploadSection] = useState(false);
  const [jsonData, setJsonData] = useState(null);

  useEffect(() => {
    const timer = setTimeout(() => {
      setShowButtons(true);
      console.log("Buttons should now be visible");
    }, 3500);
    return () => clearTimeout(timer);
  }, []);

  const handleFileUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const json = JSON.parse(e.target.result);
          setJsonData(json);
          console.log("JSON data uploaded", json);
        } catch (error) {
          console.error("Error parsing JSON:", error);
        }
      };
      reader.readAsText(file);
    }
  };

  const generatePDF = () => {
    if (!jsonData) {
      console.error("No data available for PDF generation.");
      return;
    }

    const doc = new jsPDF();
    doc.text("Uploaded JSON Data", 10, 10);

    let tableColumn, tableRows;
    if (Array.isArray(jsonData)) {
      tableColumn = Object.keys(jsonData[0] || {});
      tableRows = jsonData.map(item => tableColumn.map(fieldName => item[fieldName]));
    } else {
      tableColumn = Object.keys(jsonData);
      tableRows = [Object.values(jsonData).map(value =>
        Array.isArray(value) || typeof value === 'object' ? JSON.stringify(value) : value)];
    }

    doc.autoTable({
      head: [tableColumn],
      body: tableRows,
      startY: 20,
      theme: 'grid',
      headStyles: { fillColor: [0, 123, 255], textColor: [255, 255, 255], fontStyle: 'bold' },
      styles: { fontSize: 10, cellPadding: 8, overflow: 'linebreak' },
      columnStyles: {
        0: { cellWidth: 'auto' },
        1: { cellWidth: 'auto' },
        2: { cellWidth: 'auto' },
      },
    });

    doc.save('report.pdf');
    console.log("PDF generated");
  };

  const renderTable = () => {
    if (!jsonData) {
      return <p>No data available. Please upload a JSON file.</p>;
    }

    let columns, rows;
    if (Array.isArray(jsonData)) {
      columns = Object.keys(jsonData[0] || {});
      rows = jsonData;
    } else {
      columns = Object.keys(jsonData);
      rows = [jsonData];
    }

    return (
      <div className="table-section">
        <div className="table-container">
          <table className="json-table">
            <thead>
              <tr>
                {columns.map((col, index) => <th key={index}>{col}</th>)}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => (
                <tr key={index}>
                  {columns.map((col, colIndex) => (
                    <td key={colIndex}>{row[col]}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  return (
    <div className="App">
      <video autoPlay loop muted className="background-video">
        <source src="/bg1.mp4" type="video/mp4" />
        Your browser does not support the video tag.
      </video>

      <header className="App-header">
        <h1 className="typewriter">Hello, welcome to Static Analysis of APK</h1>
        <img src="./cb.png" alt="Chatbot Icon" className="chatbot-icon" />
      </header>

      {showButtons && (
        <div className="button-group">
          <button onClick={() => { setShowUploadSection(true); console.log("Manifest Analysis clicked"); }}>Manifest Analysis</button>
          <button onClick={() => { setShowUploadSection(true); console.log("Lint Analysis clicked"); }}>Lint Analysis</button>
          <button onClick={() => { setShowUploadSection(true); console.log("Dependency Check clicked"); }}>Dependency Check</button>
          {/* <button onClick={() => { setShowUploadSection(true); console.log("Basic Analysis clicked"); }}>Basic Analysis</button> */}
          <button onClick={() => { setShowUploadSection(true); console.log("In-depth Analysis clicked"); }}>In-depth Analysis</button>
        </div>
      )}

      {showUploadSection && (
        <div className="upload-section">
          <h1>Upload JSON File</h1>
          <input type="file" accept=".json" onChange={handleFileUpload} />
          <h2>JSON to Table</h2>
          {renderTable()}
          <div className="pdf-button-container">
            <button onClick={generatePDF} disabled={!jsonData}>
              Convert to PDF
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;