import { observer } from 'mobx-react-lite';
import React from 'react';
import { Route , Routes } from 'react-router-dom';

import HomePage from './pages/HomePage/HomePage';

import './App.css';
import { Header } from './components/Header/Header';

function App() {
  return (
    <>
      <Header/>
      <Routes>
        <Route path='*' element={<HomePage/>} />
      </Routes>
    </>
  );
}

export default observer(App);
