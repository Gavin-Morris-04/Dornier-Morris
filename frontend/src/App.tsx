import { useEffect, useState } from 'react';

export default function App() {
  const [aiScore, setAiScore] = useState<number | null>(null);
  const [loading, setLoading] = useState<boolean>(false);

  useEffect(() => {
    // Event Handler whenever user switches emails
    const handleItemChange = () => {
      const item = Office.context.mailbox.item;
      if (!item) return;

      setLoading(true);

      // Extract the body content of the email
      item.body.getAsync(Office.CoercionType.Text, (result) => {
        if (result.status === Office.AsyncResultStatus.Succeeded) {
          const emailText = result.value;

          // Call your local FastAPI Backend
          fetch('http://localhost:8000/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text: emailText })
          })
          .then(res => res.json())
          .then(data => {
            setAiScore(data.ai_confidence);
            setLoading(false);
          })
          .catch(() => setLoading(false));
        }
      });
    };

    // Register event listener with Outlook
    Office.context.mailbox.addHandlerAsync(Office.EventType.ItemChanged, handleItemChange);

    // Initial check on load
    handleItemChange();
  }, []);

  return (
    <div style={{ padding: '16px', fontFamily: 'sans-serif' }}>
      <h2 style={{ borderBottom: '1px solid #ccc', paddingBottom: '8px' }}>Security Analysis</h2>
      {loading ? (
        <p>Analyzing email context...</p>
      ) : (
        <div>
          <h3>🤖 AI Generation Risk</h3>
          <p style={{ fontSize: '24px', fontWeight: 'bold', color: aiScore && aiScore > 70 ? 'red' : 'green' }}>
            {aiScore !== null ? `${aiScore}%` : 'N/A'}
          </p>
          
          <h3>🎣 Phishing Threat Level</h3>
          <p style={{ color: 'gray', fontStyle: 'italic' }}>Phase 2 Engine Offline</p>
        </div>
      )}
    </div>
  );
}