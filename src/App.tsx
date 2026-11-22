import { DataByokPage } from './pages/DataByokPage';

export default function App() {
  const handleBack = () => {
    window.location.href =
      window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
        ? 'http://localhost:5173/'
        : 'https://0trust.dev/';
  };

  return <DataByokPage onBack={handleBack} />;
}
