import { useEffect, useState } from 'react';

interface PhishingResult {
  score: number;
  level: 'low' | 'medium' | 'high';
  reasons: string[];
  links: string[];
}

interface AnalysisResult {
  ai_confidence: number;
  ai_method: string;
  phishing: PhishingResult;
}

const API_URL = 'http://localhost:8000/api/analyze';

export default function App() {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState<boolean>(false);

  useEffect(() => {
    // Office.onReady guarantees the Office.js runtime is initialized before we
    // touch the mailbox. Calling handleItemChange() outside this caused the
    // first email to intermittently fail to analyze.
    Office.onReady(() => {
      const handleItemChange = () => {
        const item = Office.context.mailbox.item;
        if (!item) return;

        setLoading(true);
        item.body.getAsync(Office.CoercionType.Text, (res) => {
          if (res.status !== Office.AsyncResultStatus.Succeeded) {
            setLoading(false);
            return;
          }
          fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text: res.value }),
          })
            .then((r) => r.json())
            .then((data: AnalysisResult) => {
              setResult(data);
              setLoading(false);
            })
            .catch(() => setLoading(false));
        });
      };

      Office.context.mailbox.addHandlerAsync(Office.EventType.ItemChanged, handleItemChange);
      handleItemChange(); // analyze whatever email is open on load
    });
  }, []);

  const ai = result?.ai_confidence ?? null;
  const phish = result?.phishing;
  const levelColor =
    phish?.level === 'high' ? 'red' : phish?.level === 'medium' ? '#d18b00' : 'green';

  return (
    <div style={{ padding: '16px', fontFamily: 'sans-serif' }}>
      <h2 style={{ borderBottom: '1px solid #ccc', paddingBottom: '8px' }}>Security Analysis</h2>

      {loading ? (
        <p>Analyzing email context...</p>
      ) : (
        <div>
          <h3>🤖 AI Generation Risk</h3>
          <p style={{ fontSize: '24px', fontWeight: 'bold', color: ai && ai > 70 ? 'red' : 'green' }}>
            {ai !== null ? `${ai}%` : 'N/A'}
          </p>
          {result && (
            <p style={{ fontSize: '11px', color: '#888', marginTop: '-8px' }}>
              engine: {result.ai_method}
            </p>
          )}

          <h3>🎣 Phishing Threat Level</h3>
          {phish ? (
            <>
              <p style={{ fontSize: '20px', fontWeight: 'bold', color: levelColor }}>
                {phish.level.toUpperCase()} ({phish.score}%)
              </p>
              {phish.reasons.length > 0 && (
                <ul style={{ fontSize: '13px', color: '#444' }}>
                  {phish.reasons.map((r, i) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              )}
              {phish.links.length > 0 && (
                <p style={{ fontSize: '12px', color: '#666' }}>
                  {phish.links.length} link(s) found — crawler check coming in Phase 2.
                </p>
              )}
            </>
          ) : (
            <p style={{ color: 'gray', fontStyle: 'italic' }}>N/A</p>
          )}
        </div>
      )}
    </div>
  );
}
