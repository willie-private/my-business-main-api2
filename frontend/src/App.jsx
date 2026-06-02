import { Route, Routes } from 'react-router-dom';
import Login from './pages/common/Login';
function App() {

  return (
    <>
      <Routes>
        <Route>
          <Route path='*' element={<Login />} />
        </Route>
      </Routes>
    </>
  );
}

export default App;
