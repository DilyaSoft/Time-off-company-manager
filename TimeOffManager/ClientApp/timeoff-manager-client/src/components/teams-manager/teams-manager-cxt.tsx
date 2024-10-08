import { createContext, ReactNode, useContext, useState } from 'react';

interface DataContextType {
    data: string | null;
    setData: (data: string) => void;
}

let cxt:DataContextType = {data: "", setData: () => {}}; 
const DataContext = createContext<DataContextType>(cxt);



export const TeamsManagerProvider = ({ children }: { children: ReactNode }) => {
    const [data, setData] = useState<string | null>(null);

  return (
    <DataContext.Provider value={{ data, setData }}>
      {children}
    </DataContext.Provider>
  );
};

export const useSharedTeamsData = (): DataContextType => {
    const context = useContext(DataContext);
    return context;
  };