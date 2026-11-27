import { resetByokEngineStore } from './engine/dataByokEngine';
import { DataByokPage } from './pages/DataByokPage';
import { LabLeaseGuard } from './shell';

export default function App() {
  const handleBack = () => {
    window.location.href =
      window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
        ? 'http://localhost:5173/'
        : 'https://0trust.dev/';
  };

  return (
    <LabLeaseGuard
      labSlug="data-byok"
      labTitle="Data Classification, Masking & BYOK Crypto-Shredding"
      onLeaseEnded={resetByokEngineStore}
    >
      <DataByokPage onBack={handleBack} />
    </LabLeaseGuard>
  );
}
