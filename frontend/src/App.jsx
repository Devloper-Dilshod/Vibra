import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import {
    Send, LogOut, User as UserIcon, Shield, Trash2,
    Settings, Search, MessageSquare,
    Users, Bell, Info, Edit, X, CheckCheck, Loader2, AlertCircle, Lock, CornerUpLeft, ArrowDown
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import * as THREE from 'three';

const API_BASE = 'http://localhost/VIbra/backend/index.php';

// --- Helper for Safe JSON Parsing ---
const safeJSONParse = (str) => {
    try {
        return JSON.parse(str);
    } catch (e) {
        console.error("JSON Parse Error:", e);
        return null;
    }
};

// --- 3D Background Component ---
const ThreeBackground = () => {
    const mountRef = useRef(null);
    useEffect(() => {
        if (!mountRef.current) return;
        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
        const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
        renderer.setSize(window.innerWidth, window.innerHeight);
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        mountRef.current.appendChild(renderer.domElement);

        const particlesGeometry = new THREE.BufferGeometry();
        const count = 1200;
        const positions = new Float32Array(count * 3);
        for (let i = 0; i < count * 3; i++) positions[i] = (Math.random() - 0.5) * 10;
        particlesGeometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        const material = new THREE.PointsMaterial({ size: 0.012, color: '#0ea5e9', transparent: true, opacity: 0.5, blending: THREE.AdditiveBlending });
        const points = new THREE.Points(particlesGeometry, material);
        scene.add(points);
        camera.position.z = 2;

        let frameId;
        const animate = () => {
            frameId = requestAnimationFrame(animate);
            points.rotation.y += 0.0008;
            points.rotation.x += 0.0004;
            renderer.render(scene, camera);
        };
        animate();

        const handleResize = () => {
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        };
        window.addEventListener('resize', handleResize);
        return () => {
            window.removeEventListener('resize', handleResize);
            cancelAnimationFrame(frameId);
            if (mountRef.current) mountRef.current.removeChild(renderer.domElement);
            renderer.dispose();
            material.dispose();
            particlesGeometry.dispose();
        };
    }, []);
    return <div ref={mountRef} className="fixed inset-0 z-0 pointer-events-none opacity-40" />;
};

// --- Custom Components ---
const VerifiedIcon = ({ className }) => (
    <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24">
        <path fill="#3747D6" d="M13.548 1.31153C12.7479 0.334164 11.2532 0.334167 10.453 1.31153L9.46119 2.52298L7.99651 1.96975C6.81484 1.52343 5.52046 2.27074 5.31615 3.51726L5.06292 5.06232L3.51785 5.31556C2.27134 5.51986 1.52402 6.81424 1.97035 7.99591L2.52357 9.4606L1.31212 10.4524C0.334759 11.2526 0.334762 12.7473 1.31213 13.5475L2.52357 14.5393L1.97035 16.004C1.52402 17.1856 2.27133 18.48 3.51785 18.6843L5.06292 18.9376L5.31615 20.4826C5.52046 21.7291 6.81484 22.4765 7.99651 22.0301L9.46119 21.4769L10.453 22.6884C11.2532 23.6657 12.7479 23.6657 13.548 22.6884L14.5399 21.4769L16.0046 22.0301C17.1862 22.4765 18.4806 21.7291 18.6849 20.4826L18.9382 18.9376L20.4832 18.6843C21.7297 18.48 22.4771 17.1856 22.0307 16.004L21.4775 14.5393L22.689 13.5474C23.6663 12.7473 23.6663 11.2526 22.689 10.4524L21.4775 9.4606L22.0307 7.99591C22.4771 6.81425 21.7297 5.51986 20.4832 5.31556L18.9382 5.06232L18.6849 3.51726C18.4806 2.27074 17.1862 1.52342 16.0046 1.96975L14.5399 2.52298L13.548 1.31153Z" />
        <path fill="#90CAEA" fillRule="evenodd" d="M18.2072 9.20711L11.2072 16.2071C11.0196 16.3946 10.7653 16.5 10.5001 16.5C10.2349 16.5 9.9805 16.3946 9.79297 16.2071L5.79297 12.2071L7.20718 10.7929L10.5001 14.0858L16.793 7.79289L18.2072 9.20711Z" clipRule="evenodd" />
    </svg>
);

const Modal = ({ isOpen, onClose, title, children, footer }) => (
    <AnimatePresence>
        {isOpen && (
            <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose} className="absolute inset-0 bg-slate-900/40 backdrop-blur-sm" />
                <motion.div initial={{ opacity: 0, scale: 0.95, y: 20 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.95, y: 20 }} className="relative w-full max-w-md bg-white rounded-[2rem] shadow-2xl overflow-hidden">
                    <div className="p-8">
                        <h3 className="text-xl font-black text-slate-900 mb-4 tracking-tight">{title}</h3>
                        <div className="text-slate-600 font-medium leading-relaxed">{children}</div>
                    </div>
                    {footer && <div className="p-6 bg-slate-50 flex gap-3 justify-end border-t border-slate-100">{footer}</div>}
                </motion.div>
            </div>
        )}
    </AnimatePresence>
);

export default function App() {
    const [user, setUser] = useState(() => safeJSONParse(localStorage.getItem('vibra_user') || 'null'));
    const [messages, setMessages] = useState([]);
    const [input, setInput] = useState('');
    const [isAuth, setIsAuth] = useState(!user);
    const [authMode, setAuthMode] = useState('login');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [ipBlocked, setIpBlocked] = useState(false);
    const [mutedUntil, setMutedUntil] = useState(null);
    const [timeLeft, setTimeLeft] = useState(0);

    const [editingMsg, setEditingMsg] = useState(null);
    const [editInput, setEditInput] = useState('');
    const [replyingTo, setReplyingTo] = useState(null);
    const [deleteModal, setDeleteModal] = useState({ open: false, id: null });
    const [adminModal, setAdminModal] = useState(false);
    const [userList, setUserList] = useState([]);
    const [loading, setLoading] = useState(false);

    const scrollRef = useRef(null);
    const messageRefs = useRef({});

    useEffect(() => {
        if (user && user.id && !ipBlocked) {
            fetchMessages();
            const interval = setInterval(fetchMessages, 3000);
            return () => clearInterval(interval);
        }
    }, [user, ipBlocked]);

    useEffect(() => {
        if (scrollRef.current && !replyingTo) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [messages, replyingTo]);

    // Mute Countdown Logic
    useEffect(() => {
        let timer;
        if (mutedUntil) {
            const remaining = Math.max(0, Math.floor((new Date(mutedUntil).getTime() - new Date().getTime()) / 1000));
            setTimeLeft(remaining);
            if (remaining > 0) {
                timer = setInterval(() => {
                    setTimeLeft((prev) => {
                        if (prev <= 1) {
                            clearInterval(timer);
                            return 0;
                        }
                        return prev - 1;
                    });
                }, 1000);
            }
        }
        return () => clearInterval(timer);
    }, [mutedUntil]);

    const fetchMessages = async () => {
        if (!user || !user.id || ipBlocked) return;
        try {
            const res = await axios.get(`${API_BASE}/chat/messages?user_id=${user.id}`);
            const data = res.data;
            if (data && Array.isArray(data.messages)) {
                setMessages(data.messages);
                if (data.muted_until) setMutedUntil(data.muted_until);

                const isNowBlocked = !!Number(data.is_blocked || 0);
                const isCurrentlyBlocked = !!Number(user.is_blocked || 0);
                if (isNowBlocked !== isCurrentlyBlocked) {
                    const updatedUser = { ...user, is_blocked: isNowBlocked ? 1 : 0 };
                    localStorage.setItem('vibra_user', JSON.stringify(updatedUser));
                    setUser(updatedUser);
                }
            }
        } catch (err) {
            console.error('Fetch Error:', err);
            if (err.response?.status === 403) setIpBlocked(true);
        }
    };

    const fetchUsers = async () => {
        if (!user || user.role !== 'admin') return;
        try {
            const res = await axios.get(`${API_BASE}/admin/users?admin_id=${user.id}`);
            if (Array.isArray(res.data)) setUserList(res.data);
        } catch (err) {
            console.error('Admin Fetch Error');
        }
    };

    const handleAuth = async (e) => {
        e.preventDefault();
        setError('');

        const usernameRegex = /^[a-zA-Z0-9_]+$/;
        if (!usernameRegex.test(username)) {
            setError("Username faqat harf, raqam va '_' belgisi mumkin!");
            return;
        }

        setLoading(true);
        try {
            const endpoint = authMode === 'login' ? 'auth/login' : 'auth/register';
            const res = await axios.post(`${API_BASE}/${endpoint}`, { username, password });
            if (res.data && res.data.user) {
                localStorage.setItem('vibra_user', JSON.stringify(res.data.user));
                setUser(res.data.user);
                setIsAuth(false);
            } else {
                setError('Ma\'lumot olishda xatolik');
            }
        } catch (err) {
            if (err.response?.status === 403) {
                setIpBlocked(true);
            } else {
                setError(err.response?.data?.error || 'Xatolik yuz berdi');
            }
        } finally {
            setLoading(false);
        }
    };

    const sendMessage = async (e) => {
        e.preventDefault();
        if (!input.trim() || !user || user.is_blocked || timeLeft > 0) return;
        try {
            await axios.post(`${API_BASE}/chat/send`, { user_id: user.id, message: input, reply_to: replyingTo?.id });
            setInput('');
            setReplyingTo(null);
            fetchMessages();
        } catch (err) {
            if (err.response?.status === 403 && err.response?.data?.muted_until) {
                setMutedUntil(err.response.data.muted_until);
            } else if (err.response?.status === 403) {
                setIpBlocked(true);
            } else {
                alert(err.response?.data?.error || 'Xabar yuborishda xatolik');
            }
        }
    };

    const startEdit = (msg) => {
        setEditingMsg(msg);
        setEditInput(msg.message);
    };

    const saveEdit = async () => {
        if (!editInput.trim() || !user) return;
        try {
            await axios.post(`${API_BASE}/chat/edit`, { id: editingMsg.id, user_id: user.id, message: editInput });
            setEditingMsg(null);
            fetchMessages();
        } catch (err) {
            alert('Tahrirlashda xatolik');
        }
    };

    const confirmDelete = async () => {
        if (!user) return;
        try {
            await axios.post(`${API_BASE}/chat/delete`, { id: deleteModal.id, user_id: user.id });
            setDeleteModal({ open: false, id: null });
            fetchMessages();
        } catch (err) {
            alert('O\'chirishda xatolik');
        }
    };

    const toggleBlock = async (targetId, isBlocked) => {
        if (!user) return;
        const endpoint = isBlocked ? 'unblock' : 'block';
        try {
            await axios.post(`${API_BASE}/admin/${endpoint}`, { user_id: targetId, admin_id: user.id });
            fetchUsers();
        } catch (err) {
            alert('Operatsiyada xatolik');
        }
    };

    const scrollToMessage = (id) => {
        const el = messageRefs.current[id];
        if (el) {
            el.scrollIntoView({ behavior: 'smooth', block: 'center' });
            el.classList.add('ring-4', 'ring-sky-400/50', 'ring-offset-2');
            setTimeout(() => el.classList.remove('ring-4', 'ring-sky-400/50', 'ring-offset-2'), 2000);
        }
    };

    const logout = () => {
        localStorage.removeItem('vibra_user');
        setUser(null);
        setIsAuth(true);
        setMessages([]);
    };

    const formatMuteTime = (sec) => {
        const m = Math.floor(sec / 60);
        const s = sec % 60;
        return `${m}:${s < 10 ? '0' : ''}${s}`;
    };

    if (ipBlocked) {
        return (
            <div className="min-h-screen bg-slate-900 flex flex-col items-center justify-center p-6 text-center font-outfit">
                <motion.div initial={{ scale: 0.8, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} className="bg-white/5 backdrop-blur-xl p-12 rounded-[3rem] border border-white/10 shadow-2xl max-w-lg w-full">
                    <div className="w-24 h-24 bg-red-500/20 rounded-full flex items-center justify-center mx-auto mb-8 animate-pulse">
                        <Lock className="w-12 h-12 text-red-500" />
                    </div>
                    <h1 className="text-4xl font-black text-white mb-4">Siz bloklangansiz</h1>
                    <p className="text-slate-400 font-medium leading-relaxed mb-8">Havfsizlik qoidalariga amal qilmaganingiz sababli tizimga kirish imkoni yo'q.</p>
                    <div className="h-1 w-20 bg-red-500 mx-auto rounded-full mb-8" />
                    <p className="text-[10px] text-slate-500 uppercase font-black tracking-widest">Support: @dilshod_Sayfiddinov</p>
                </motion.div>
            </div>
        );
    }

    if (isAuth || !user) {
        return (
            <div className="min-h-screen bg-slate-900 flex flex-col items-center justify-center p-6 font-outfit relative overflow-hidden">
                <ThreeBackground />
                <motion.div initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} className="w-full max-w-md bg-white/10 backdrop-blur-2xl p-10 md:p-12 rounded-[3rem] shadow-2xl border border-white/20 z-10">
                    <div className="text-center mb-10">
                        <motion.h1 initial={{ scale: 0.9 }} animate={{ scale: 1 }} className="text-6xl font-black text-white tracking-tighter mb-2">Vibra<span className="text-sky-500">.</span></motion.h1>
                        <p className="text-sky-400/80 font-black uppercase text-[10px] tracking-[0.3em]">{authMode === 'login' ? 'Xush kelibsiz' : 'Akkaunt ochish'}</p>
                    </div>
                    <form onSubmit={handleAuth} className="space-y-6">
                        <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} className="w-full bg-white/5 border-2 border-white/10 rounded-2xl py-5 px-8 focus:outline-none focus:border-sky-500 transition-all font-semibold text-white placeholder-slate-500" placeholder="Username" />
                        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="w-full bg-white/5 border-2 border-white/10 rounded-2xl py-5 px-8 focus:outline-none focus:border-sky-500 transition-all font-semibold text-white placeholder-slate-500" placeholder="Password" />
                        {error && <div className="p-4 bg-red-500/10 text-red-400 rounded-2xl text-xs font-bold border border-red-500/20 flex items-center gap-2"><AlertCircle className="w-4 h-4" />{error}</div>}
                        <button type="submit" disabled={loading} className="w-full bg-sky-500 hover:bg-sky-400 text-white font-black py-5 rounded-2xl shadow-2xl active:scale-95 transition-all outline-none">
                            {loading ? <Loader2 className="w-5 h-5 animate-spin mx-auto" /> : (authMode === 'login' ? 'Kirish' : 'Qo\'shilish')}
                        </button>
                    </form>
                    <button onClick={() => setAuthMode(authMode === 'login' ? 'register' : 'login')} className="w-full mt-8 text-slate-400 hover:text-white transition-all text-xs font-black uppercase tracking-widest">
                        {authMode === 'login' ? "Akkaunt ochish" : "Kirishga o'tish"}
                    </button>
                </motion.div>
            </div>
        );
    }

    return (
        <div className="h-screen bg-slate-50 flex flex-col md:flex-row font-outfit overflow-hidden">
            <div className="hidden md:flex w-24 bg-white border-r border-slate-100 flex-col items-center py-12 space-y-12 z-30 shadow-sm">
                <div className="w-14 h-14 bg-sky-500 rounded-[1.5rem] flex items-center justify-center shadow-2xl shadow-sky-200 rotate-12"><MessageSquare className="w-7 h-7 text-white" /></div>
                <div className="flex-1"></div>
                <button onClick={logout} className="p-4 bg-red-50 text-red-500 rounded-2xl hover:bg-red-500 hover:text-white transition-all shadow-lg active:scale-90"><LogOut className="w-6 h-6" /></button>
            </div>

            <div className="flex-1 flex flex-col h-full relative">
                <div className="bg-white/95 backdrop-blur-md border-b border-slate-100 p-6 flex justify-between items-center z-20 shadow-sm">
                    <div className="flex items-center gap-3">
                        <h3 className={`font-black text-slate-900 text-2xl tracking-tighter ${(user.role === 'admin' && !user.is_blocked) ? 'cursor-pointer hover:text-sky-600' : ''}`} onClick={() => { if (user.role === 'admin' && !user.is_blocked) { setAdminModal(true); fetchUsers(); } }}>Vibra<span className="text-sky-500">.</span>Global</h3>
                    </div>
                    <div className="flex items-center gap-4">
                        <div className={`p-2 px-4 rounded-xl text-xs font-black ${timeLeft > 0 ? 'bg-amber-50 text-amber-600' : 'bg-slate-50 text-slate-400'}`}>
                            {timeLeft > 0 ? `Anti-Flood: ${formatMuteTime(timeLeft)}` : 'Suhbatga tayyor'}
                        </div>
                        <div className={`flex items-center gap-2 px-5 py-2.5 rounded-2xl border ${user.is_blocked ? 'bg-red-50 border-red-100' : 'bg-slate-50 border-slate-100'}`}>
                            <span className={`text-sm font-black ${user.is_blocked ? 'text-red-500' : 'text-slate-700'}`}>{user.username} {user.is_blocked ? '(Blok)' : ''}</span>
                            {user.is_verified ? <VerifiedIcon className="w-5 h-5" /> : null}
                        </div>
                    </div>
                </div>

                <div ref={scrollRef} className="flex-1 overflow-y-auto px-6 md:px-16 py-12 space-y-10 scroll-smooth bg-slate-50/50">
                    {Array.isArray(messages) && messages.map((msg) => (
                        <motion.div ref={el => messageRefs.current[msg.id] = el} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} key={msg.id} className={`flex flex-col group ${msg.username === user.username ? 'items-end' : 'items-start'}`}>
                            <div className="flex items-center gap-2 mb-1.5 px-3">
                                <span className="text-[10px] font-black uppercase text-slate-400 tracking-widest">{msg.username}</span>
                                {msg.is_verified ? <VerifiedIcon className="w-4 h-4" /> : null}
                                <span className="text-[9px] text-slate-300 font-bold ml-1">{msg.created_at ? new Date(msg.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''}</span>
                            </div>

                            <div className={`relative px-6 py-4 rounded-[2rem] max-w-[85%] md:max-w-[60%] shadow-md transition-all ${msg.username === user.username ? 'bg-slate-900 text-white rounded-tr-none' : 'bg-white text-slate-800 rounded-tl-none border border-slate-100'}`}>
                                {msg.parent_message && (
                                    <div
                                        onClick={() => scrollToMessage(msg.reply_to)}
                                        className="mb-2 p-3 bg-sky-500/10 rounded-xl border-l-[3px] border-sky-400 text-[11px] font-medium opacity-90 overflow-hidden cursor-pointer hover:bg-sky-500/20 transition-all active:scale-95 group/reply"
                                    >
                                        <span className="font-black text-sky-500 flex items-center gap-1.5 mb-0.5 uppercase tracking-tighter">
                                            <CornerUpLeft className="w-3 h-3" /> {msg.parent_username}
                                        </span>
                                        <p className="text-slate-500 truncate">{msg.parent_message}</p>
                                    </div>
                                )}
                                {editingMsg?.id === msg.id ? (
                                    <div className="space-y-4">
                                        <textarea autoFocus value={editInput} onChange={(e) => setEditInput(e.target.value)} className="w-full bg-slate-800 text-white p-4 rounded-2xl focus:outline-none border border-slate-700 font-medium h-24 resize-none font-outfit" />
                                        <div className="flex justify-end gap-3"><button onClick={() => setEditingMsg(null)}><X className="w-6 h-6 text-slate-400" /></button><button onClick={saveEdit} className="p-2 bg-sky-500 rounded-xl text-white"><CheckCheck className="w-5 h-5" /></button></div>
                                    </div>
                                ) : (
                                    <>
                                        <p className="text-[16px] font-medium leading-relaxed whitespace-pre-wrap">{msg.message}</p>
                                        <div className="flex items-center justify-end gap-1.5 mt-2 opacity-60">
                                            {msg.is_edited ? <span className="text-[8px] font-black uppercase text-slate-400 tracking-tighter mr-1">Tahrirlandi</span> : null}
                                            {msg.username === user.username ? (
                                                msg.is_seen ? <CheckCheck className="w-4 h-4 text-sky-400 scale-110" /> : <CheckCheck className="w-4 h-4 text-slate-500 opacity-30" />
                                            ) : null}
                                        </div>
                                    </>
                                )}
                                <div className={`absolute top-0 flex gap-1.5 transition-all opacity-0 group-hover:opacity-100 ${msg.username === user.username ? 'right-full mr-4' : 'left-full ml-4'} pt-1`}>
                                    <button onClick={() => setReplyingTo(msg)} title="Javob berish" className="p-3 bg-white text-slate-400 hover:text-sky-500 rounded-2xl border border-slate-100 shadow-xl active:scale-90"><CornerUpLeft className="w-4 h-4" /></button>
                                    {msg.username === user.username && !editingMsg && !user.is_blocked && <button onClick={() => startEdit(msg)} title="Tahrirlash" className="p-3 bg-white text-slate-400 hover:text-sky-600 rounded-2xl border border-slate-100 shadow-xl active:scale-90"><Edit className="w-4 h-4" /></button>}
                                    {(user.role === 'admin' || msg.username === user.username) && !user.is_blocked && (
                                        <button onClick={() => setDeleteModal({ open: true, id: msg.id })} title="O'chirish" className="p-3 bg-white text-slate-400 hover:text-red-500 rounded-2xl border border-slate-100 shadow-xl active:scale-90">
                                            <Trash2 className="w-4 h-4" />
                                        </button>
                                    )}
                                </div>
                            </div>
                        </motion.div>
                    ))}
                </div>

                <div className="p-8 md:p-12 bg-white/50 backdrop-blur-sm border-t border-slate-100">
                    <div className="max-w-4xl mx-auto space-y-4">
                        <AnimatePresence>
                            {replyingTo && (
                                <motion.div initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: 15 }} className="flex items-center justify-between p-4 bg-sky-500/5 rounded-2xl border border-sky-100 group">
                                    <div className="flex items-center gap-4 overflow-hidden">
                                        <div className="p-2 bg-sky-500 rounded-xl text-white shadow-lg shadow-sky-200"><CornerUpLeft className="w-4 h-4" /></div>
                                        <div className="overflow-hidden">
                                            <p className="text-[10px] font-black text-sky-500 uppercase tracking-widest">{replyingTo.username} ga javob</p>
                                            <p className="text-sm text-slate-600 font-medium truncate italic">{replyingTo.message}</p>
                                        </div>
                                    </div>
                                    <button onClick={() => setReplyingTo(null)} className="p-2 text-slate-400 hover:text-red-500 transition-colors"><X className="w-6 h-6" /></button>
                                </motion.div>
                            )}
                        </AnimatePresence>
                        {timeLeft > 0 ? (
                            <div className="w-full bg-amber-50 border-2 border-amber-100 text-amber-600 p-8 rounded-[2.5rem] flex items-center justify-center gap-4 font-black shadow-xl">
                                <AlertCircle className="w-8 h-8" />
                                Sizga mute berildi! Kutishingiz kerak: {formatMuteTime(timeLeft)}
                            </div>
                        ) : user.is_blocked ? (
                            <div className="w-full bg-red-50 border-2 border-red-100 text-red-500 p-8 rounded-[2.5rem] flex items-center justify-center gap-4 font-black shadow-xl">
                                <AlertCircle className="w-8 h-8" />
                                Siz bloklangansiz! Ma'muriyat bilan bog'laning.
                            </div>
                        ) : (
                            <form onSubmit={sendMessage} className="relative flex items-center group">
                                <input value={input} onChange={(e) => setInput(e.target.value)} placeholder={replyingTo ? "Javob yozing..." : "Xabar yozing..."} className="w-full bg-white border-2 border-slate-100 rounded-[2.5rem] py-8 px-12 focus:outline-none focus:border-sky-500/50 shadow-2xl shadow-slate-200/50 text-slate-800 font-semibold text-lg transition-all" />
                                <button type="submit" className="absolute right-4 p-6 bg-sky-500 text-white rounded-[2rem] hover:bg-sky-600 transition-all active:scale-95 shadow-2xl shadow-sky-200"><Send className="w-8 h-8" /></button>
                            </form>
                        )}
                    </div>
                </div>
            </div>

            <Modal isOpen={deleteModal.open} onClose={() => setDeleteModal({ open: false, id: null })} title="O'chirish" footer={<><button onClick={() => setDeleteModal({ open: false, id: null })} className="px-8 py-3 font-black text-slate-400">Yo'q</button><button onClick={confirmDelete} className="px-10 py-3 bg-red-500 text-white font-black rounded-2xl shadow-2xl">O'chirish</button></>}>Ushbu xabarni butunlay o'chirib tashlaysizmi?</Modal>
            <Modal isOpen={adminModal} onClose={() => setAdminModal(false)} title="Boshqaruv Paneli" footer={<button onClick={() => setAdminModal(false)} className="px-12 py-5 bg-slate-900 text-white font-black rounded-3xl shadow-2xl">Yopish</button>}>
                <div className="space-y-5 max-h-[500px] overflow-y-auto pr-3 custom-scrollbar">
                    {userList.map(u => (
                        <div key={u.id} className="flex items-center justify-between p-6 bg-slate-50 rounded-[2rem] border border-slate-100 group transition-all">
                            <div className="flex items-center gap-4">
                                <div className={`w-14 h-14 rounded-2xl flex items-center justify-center ${u.role === 'admin' ? 'bg-sky-100 text-sky-600' : 'bg-slate-200 text-slate-500 shadow-inner'}`}><UserIcon className="w-7 h-7" /></div>
                                <div>
                                    <p className="font-black text-slate-900 text-lg">{u.username}</p>
                                    <p className="text-[10px] text-slate-400 font-bold uppercase tracking-widest">{u.role}</p>
                                </div>
                            </div>
                            {u.username !== user.username && <button onClick={() => toggleBlock(u.id, u.is_blocked)} className={`px-8 py-3 rounded-2xl text-xs font-black shadow-lg transition-all active:scale-90 ${u.is_blocked ? 'bg-emerald-500 text-white shadow-emerald-100' : 'bg-red-500 text-white shadow-red-100'}`}>{u.is_blocked ? 'Aktivlash' : 'Bloklash'}</button>}
                        </div>
                    ))}
                </div>
            </Modal>
            <style>{`.custom-scrollbar::-webkit-scrollbar { width: 5px; } .custom-scrollbar::-webkit-scrollbar-thumb { background: #e2e8f0; border-radius: 20px; }`}</style>
        </div>
    );
}
