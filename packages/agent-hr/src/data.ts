// Toy in-memory HR data. No database: restarting this agent resets it, same spirit as the rest of this demo
// (compare packages/retail-portal/src/data.ts). All names and emails are fictional.
export type Employee = {
  name: string;
  title: string;
  department: string;
  manager: string;
  email: string;
  ptoBalanceDays: number;
};

export const employees: Employee[] = [
  { name: 'Priya Natarajan', title: 'Field Service Engineer', department: 'HPE Services', manager: 'Daniel Osei', email: 'priya.natarajan@hpe-demo.example', ptoBalanceDays: 14 },
  { name: 'Marcus Webb', title: 'Account Manager', department: 'HPE Sales', manager: 'Daniel Osei', email: 'marcus.webb@hpe-demo.example', ptoBalanceDays: 6 },
  { name: 'Daniel Osei', title: 'Regional Manager', department: 'HPE Sales', manager: 'Linh Tran', email: 'daniel.osei@hpe-demo.example', ptoBalanceDays: 21 },
  { name: 'Sofia Alvarez', title: 'Warehouse Supervisor', department: 'HPE Order Fulfillment', manager: 'Linh Tran', email: 'sofia.alvarez@hpe-demo.example', ptoBalanceDays: 9 },
  { name: 'Linh Tran', title: 'VP, Order Operations', department: 'HPE Order Operations', manager: '(none)', email: 'linh.tran@hpe-demo.example', ptoBalanceDays: 25 },
];

/** Case-insensitive match on a (partial) name, or an exact match on email. */
export const findEmployee = (query: string): Employee | undefined => {
  const q = query.trim().toLowerCase();
  if (!q) return undefined;
  return employees.find((e) => e.name.toLowerCase().includes(q)) ?? employees.find((e) => e.email.toLowerCase() === q);
};
