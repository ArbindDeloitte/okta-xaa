// In-memory SAMPLE data for the demo HPE order portal. Resets on restart.
// Product names are HPE-style for realism; SKUs, prices, stock, accounts and orders are fictional demo values.

export type Product = { sku: string; name: string; category: string; price: number; description: string };
export type OrderStatus = 'processing' | 'shipped' | 'delivered' | 'cancelled' | 'returned';
export type OrderLine = { sku: string; qty: number; unitPrice: number };
export type Order = {
  id: string;
  customerId: string; // enterprise account id (ACC-xxx)
  status: OrderStatus;
  channel: 'direct' | 'partner';
  placedAt: string;
  deliveredAt?: string;
  items: OrderLine[];
  total: number;
  notes: string[];
};
export type Customer = {
  id: string;
  name: string; // account (company) name
  contact: string;
  email: string;
  phone: string;
  accountTier: 'Strategic' | 'Major' | 'Standard';
  annualSpendUsd: number;
};
export type ReturnStatus = 'approved' | 'pending_manager_approval';
export type ReturnRequest = {
  id: string;
  orderId: string;
  sku: string;
  qty: number;
  reason: string;
  refundAmount: number;
  status: ReturnStatus;
  createdAt: string;
  createdBy: string;
};

const daysAgo = (d: number) => new Date(Date.now() - d * 86_400_000).toISOString();

export const products: Product[] = [
  { sku: 'HPE-1001', name: 'HPE ProLiant DL380 Gen11 Server (8SFF)', category: 'servers', price: 8950.0, description: '2U rack server for virtualization and mixed workloads' },
  { sku: 'HPE-1002', name: 'HPE ProLiant DL360 Gen11 Server (10SFF)', category: 'servers', price: 6400.0, description: '1U rack server for dense compute' },
  { sku: 'HPE-2001', name: 'Aruba Instant On AP25 Wi-Fi 6 Access Point', category: 'networking', price: 189.0, description: 'Indoor Wi-Fi 6 access point' },
  { sku: 'HPE-2002', name: 'HPE 960GB SATA Mixed Use SSD', category: 'storage', price: 689.0, description: 'Hot-plug small form factor SSD' },
  { sku: 'HPE-2003', name: 'HPE 64GB DDR5 Memory Kit', category: 'components', price: 1150.0, description: 'DDR5 registered memory for ProLiant Gen11' },
  { sku: 'HPE-3001', name: 'Aruba CX 6300M 48G Switch', category: 'networking', price: 5200.0, description: '48-port stackable L3 access switch' },
  { sku: 'HPE-3002', name: 'HPE Alletra Storage MP (base system)', category: 'storage', price: 24500.0, description: 'Modular block and file storage platform' },
  { sku: 'HPE-3003', name: 'HPE Easy Install Rail Kit', category: 'components', price: 159.0, description: 'Rack rails for 2U ProLiant servers' },
  { sku: 'HPE-4001', name: 'HPE Smart Storage Battery', category: 'components', price: 89.0, description: 'Cache backup battery for Smart Array controllers' },
  { sku: 'HPE-4002', name: 'HPE 800W Flex Slot Platinum Power Supply', category: 'components', price: 329.0, description: 'Hot-plug redundant power supply' },
  { sku: 'HPE-4003', name: 'Aruba 10G SFP+ SR Transceiver', category: 'networking', price: 245.0, description: '10GbE short-range optical transceiver' },
  { sku: 'HPE-4004', name: 'HPE Cable Management Arm Kit', category: 'components', price: 79.0, description: 'Rear cable management for rack servers' },
];

export const locations = ['DC-HOUSTON', 'DC-AMSTERDAM', 'DC-SINGAPORE', 'DC-BENGALURU'] as const;

// sku -> distribution centre -> units on hand
export const inventory: Record<string, Record<string, number>> = {
  'HPE-1001': { 'DC-HOUSTON': 42, 'DC-AMSTERDAM': 18, 'DC-SINGAPORE': 3, 'DC-BENGALURU': 0 },
  'HPE-1002': { 'DC-HOUSTON': 55, 'DC-AMSTERDAM': 30, 'DC-SINGAPORE': 18, 'DC-BENGALURU': 22 },
  'HPE-2001': { 'DC-HOUSTON': 600, 'DC-AMSTERDAM': 250, 'DC-SINGAPORE': 140, 'DC-BENGALURU': 20 },
  'HPE-2002': { 'DC-HOUSTON': 300, 'DC-AMSTERDAM': 140, 'DC-SINGAPORE': 135, 'DC-BENGALURU': 128 },
  'HPE-2003': { 'DC-HOUSTON': 190, 'DC-AMSTERDAM': 0, 'DC-SINGAPORE': 49, 'DC-BENGALURU': 61 },
  'HPE-3001': { 'DC-HOUSTON': 45, 'DC-AMSTERDAM': 24, 'DC-SINGAPORE': 16, 'DC-BENGALURU': 1 },
  'HPE-3002': { 'DC-HOUSTON': 8, 'DC-AMSTERDAM': 0, 'DC-SINGAPORE': 2, 'DC-BENGALURU': 0 },
  'HPE-3003': { 'DC-HOUSTON': 330, 'DC-AMSTERDAM': 116, 'DC-SINGAPORE': 120, 'DC-BENGALURU': 90 },
  'HPE-4001': { 'DC-HOUSTON': 500, 'DC-AMSTERDAM': 160, 'DC-SINGAPORE': 175, 'DC-BENGALURU': 144 },
  'HPE-4002': { 'DC-HOUSTON': 175, 'DC-AMSTERDAM': 68, 'DC-SINGAPORE': 0, 'DC-BENGALURU': 55 },
  'HPE-4003': { 'DC-HOUSTON': 410, 'DC-AMSTERDAM': 125, 'DC-SINGAPORE': 131, 'DC-BENGALURU': 119 },
  'HPE-4004': { 'DC-HOUSTON': 800, 'DC-AMSTERDAM': 290, 'DC-SINGAPORE': 320, 'DC-BENGALURU': 270 },
};

// Fictional enterprise accounts (not real companies).
export const customers: Customer[] = [
  { id: 'ACC-001', name: 'Meridian Health Systems', contact: 'Ava Thompson', email: 'ava.thompson@meridian-health.example', phone: '+1-713-555-0101', accountTier: 'Strategic', annualSpendUsd: 4_820_000 },
  { id: 'ACC-002', name: 'Atlas Logistics Group', contact: 'Liam Nguyen', email: 'liam.nguyen@atlas-logistics.example', phone: '+65-6555-0102', accountTier: 'Major', annualSpendUsd: 1_340_000 },
  { id: 'ACC-003', name: 'Pioneer Regional Bank', contact: 'Sofia Martinez', email: 'sofia.martinez@pioneer-bank.example', phone: '+1-512-555-0103', accountTier: 'Standard', annualSpendUsd: 310_000 },
  { id: 'ACC-004', name: 'Summit Energy Partners', contact: 'Noah Patel', email: 'noah.patel@summit-energy.example', phone: '+1-415-555-0104', accountTier: 'Strategic', annualSpendUsd: 6_150_000 },
  { id: 'ACC-005', name: 'Orchid Retail Holdings', contact: 'Mia Johansson', email: 'mia.johansson@orchid-retail.example', phone: '+31-20-555-0105', accountTier: 'Major', annualSpendUsd: 980_000 },
  { id: 'ACC-006', name: 'Vanguard Telecom Services', contact: 'Ethan Brooks', email: 'ethan.brooks@vanguard-telecom.example', phone: '+91-80-5555-0106', accountTier: 'Standard', annualSpendUsd: 120_000 },
];

const line = (sku: string, qty: number): OrderLine => ({
  sku,
  qty,
  unitPrice: products.find((p) => p.sku === sku)!.price,
});

const mk = (
  id: string,
  customerId: string,
  status: OrderStatus,
  channel: Order['channel'],
  placedDaysAgo: number,
  deliveredDaysAgo: number | undefined,
  items: OrderLine[],
): Order => ({
  id,
  customerId,
  status,
  channel,
  placedAt: daysAgo(placedDaysAgo),
  deliveredAt: deliveredDaysAgo === undefined ? undefined : daysAgo(deliveredDaysAgo),
  items,
  total: Math.round(items.reduce((s, l) => s + l.qty * l.unitPrice, 0) * 100) / 100,
  notes: [],
});

export const orders: Order[] = [
  mk('SO-10001', 'ACC-001', 'delivered', 'direct', 12, 8, [line('HPE-2001', 1), line('HPE-4004', 2)]),
  mk('SO-10002', 'ACC-002', 'shipped', 'direct', 3, undefined, [line('HPE-1001', 1)]),
  mk('SO-10003', 'ACC-003', 'processing', 'partner', 1, undefined, [line('HPE-3002', 1), line('HPE-3003', 1)]),
  mk('SO-10004', 'ACC-004', 'delivered', 'direct', 50, 45, [line('HPE-3001', 1)]),
  mk('SO-10005', 'ACC-001', 'processing', 'direct', 0, undefined, [line('HPE-2003', 2)]),
  mk('SO-10006', 'ACC-005', 'delivered', 'partner', 20, 20, [line('HPE-1002', 1), line('HPE-4001', 1)]),
  mk('SO-10007', 'ACC-006', 'cancelled', 'partner', 9, undefined, [line('HPE-4002', 1)]),
  mk('SO-10008', 'ACC-004', 'delivered', 'direct', 9, 5, [line('HPE-3002', 1), line('HPE-3001', 1)]),
  mk('SO-10009', 'ACC-002', 'processing', 'direct', 2, undefined, [line('HPE-2002', 3)]),
  mk('SO-10010', 'ACC-003', 'delivered', 'partner', 15, 11, [line('HPE-4003', 2), line('HPE-2003', 1)]),
];

export const returns: ReturnRequest[] = [];

let returnSeq = 5000;
export const nextReturnId = () => `RMA-${++returnSeq}`;
