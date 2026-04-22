import React, { createContext, useState, useContext, useEffect } from 'react';

const API_URL = process.env.REACT_APP_API_URL || '/api';
const SetupContext = createContext();

export function SetupProvider({ children }) {
  const [setupState, setSetupState] = useState({
    isComplete: null, // null = loading, true = complete, false = needs setup
    currentStep: 0,
    mode: null, // 'standalone' or 'mssp'
    dbConnected: false,
    siemConfigured: false,
    adminCreated: false
  });

  useEffect(() => {
    const controller = new AbortController();
    checkSetupStatus(controller.signal);
    return () => controller.abort();
  }, []);

  const checkSetupStatus = async (signal) => {
    try {
      const fetchOptions = signal ? { signal } : {};
      const res = await fetch(`${API_URL}/setup/status`, fetchOptions);
      const data = await res.json();
      setSetupState(prev => ({
        ...prev,
        isComplete: data.isComplete,
        dbConnected: data.dbConnected,
        siemConfigured: data.siemConfigured,
        adminCreated: data.adminCreated
      }));
    } catch (err) {
      // If API fails (and it's not an abort), assume setup is needed
      if (err.name !== 'AbortError') {
        setSetupState(prev => ({ ...prev, isComplete: false }));
      }
    }
  };

  const updateSetup = (updates) => {
    setSetupState(prev => ({ ...prev, ...updates }));
  };

  const nextStep = () => {
    setSetupState(prev => ({ ...prev, currentStep: prev.currentStep + 1 }));
  };

  const prevStep = () => {
    setSetupState(prev => ({ ...prev, currentStep: Math.max(0, prev.currentStep - 1) }));
  };

  // Flip local "isComplete" state. The wizard's last step already POSTed
  // /api/setup/complete with the user's search-auth choice — this context
  // function just reflects that in local state so the UI updates without
  // an extra network round-trip.
  const completeSetup = async () => {
    setSetupState(prev => ({ ...prev, isComplete: true }));
    localStorage.setItem('setupComplete', 'true');
  };

  const resetSetup = () => {
    setSetupState({
      isComplete: false,
      currentStep: 0,
      mode: null,
      dbConnected: false,
      siemConfigured: false,
      adminCreated: false
    });
    localStorage.removeItem('setupComplete');
  };

  return (
    <SetupContext.Provider value={{
      ...setupState,
      updateSetup,
      nextStep,
      prevStep,
      completeSetup,
      resetSetup,
      checkSetupStatus
    }}>
      {children}
    </SetupContext.Provider>
  );
}

export function useSetup() {
  const context = useContext(SetupContext);
  if (!context) {
    throw new Error('useSetup must be used within a SetupProvider');
  }
  return context;
}

export default SetupContext;
