import { createContext, useContext, ReactNode } from 'react';
import { clientDatabase } from '../services/database';

interface DatabaseContextType {
    db: typeof clientDatabase;
}

const DatabaseContext = createContext<DatabaseContextType | undefined>(undefined);

export function DatabaseProvider({ children }: { children: ReactNode }) {
    return (
        <DatabaseContext.Provider value={{ db: clientDatabase }}>
            {children}
        </DatabaseContext.Provider>
    );
}

export function useDatabase() {
    const context = useContext(DatabaseContext);
    if (context === undefined) {
        throw new Error('useDatabase must be used within a DatabaseProvider');
    }
    return context;
}
