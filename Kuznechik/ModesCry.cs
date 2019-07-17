using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace Kuznechik
{
    public class ModesCry
    {

        // 1-Простая замена
        // 2-Гаммирование
        // 3-Гаммирование с обратной связью по выходу
        // 4-Простая замена с зацеплением
        // 5-Гаммирование с обратной связью по шифртексту
        // 6-Выработка имитовставки

        #region Вспомогательные операции
        private string Procedure1(string P, int l)
        {
            int r = P.Length % l;
            return (r == 0) ? P : P.PadRight(P.Length+l-r, '0');
        }
        private string Procedure2(string P, int l)
        {
            int r = P.Length % l;
            return (P + '1').PadRight(P.Length+l-r, '0');
        }
        private string Procedure3(string P, int l)
        {
            int r = P.Length % l;
            return (r==P.Length)?P: Procedure2(P,l);
        }
        private string Truncation(string P, int s) //MSB
        {
            return (P.Length<=s)?P:P.Substring(P.Length-s-1,s);
        }
        private string TruncationBack(string P, int s) //LSB
        {
            return (P.Length <= s) ? P : P.Substring(0, s);
        }
        #endregion
        private int _mode=0;
        private int _sizeBlock=0;
        private Kuznechik kz;
        public byte[] IV { get; set; }
        public int s { get; set; }
        public ModesCry(int i,int n)
        {
            _mode = i;
            _sizeBlock=n;
            kz = new Kuznechik();
        }
        public byte[] Encrypt () //Зашифрование
        {
            #region Переменные
            byte[] V = File.ReadAllBytes("input.txt");
            byte[] k = File.ReadAllBytes("key.txt");
            int NumOfBlocks;
            byte[] P;
            byte[] encrText;
            byte[,] ctr;
            byte[] block;
            byte[] originaltext;
            byte[] lastblock;
            byte[] lastoriginaltext;
            byte[] C;
            byte[] R;
            byte[] Y;
            byte[] K1, K2;
            #region B
            byte[] B;
            B = new byte[16];
            for (int i = 0; i < 15; i++)
            {
                B[i] = 0;
            }
            B[15] = 135;
            #endregion
            int m;
            #endregion
            switch (_mode)
            {
                #region Простая замена
                case 1:
                    P = ToBytes(Procedure1(To2ich(V), _sizeBlock*8));
                    encrText = new byte[P.Length];
                        NumOfBlocks = P.Length / _sizeBlock;
                        for (int i = 0; i < NumOfBlocks; i++)
                        {
                            block = new byte[_sizeBlock];
                            for (int j = 0; j < _sizeBlock; j++)
                            {
                                block[j] = P[i * _sizeBlock + j];
                            }
                            block = kz.KuzEncript(block, k);
                            for (int j = 0; j < _sizeBlock; j++)
                            {
                                encrText[i * _sizeBlock + j] = block[j];
                            }
                        }
                        return encrText;
                #endregion
                #region Гаммирование
                case 2:
                    encrText = new byte[V.Length];
                    P = V;
                    if (P.Length % _sizeBlock == 0)
                        NumOfBlocks = P.Length / _sizeBlock;
                    else
                        NumOfBlocks = P.Length / _sizeBlock+1;
                    ctr = CTR(IV, NumOfBlocks);
                        for (int i = 0; i < NumOfBlocks-1; i++)
                        {
                            block = new byte[_sizeBlock];
                            originaltext = new byte[_sizeBlock];
                            for (int j = 0; j < _sizeBlock; j++)
                            {
                                block[j] = ctr[i,j];
                                originaltext[j] = P[_sizeBlock * i + j];
                            }
                            block = kz.KuzEncript(block, k);
                            block = AddBymod2(originaltext,ToBytes(Truncation(To2ich(block), s*8)));
                            for (int j = 0; j < _sizeBlock; j++)
                            {
                                encrText[i * _sizeBlock + j] = block[j];
                            }
                        }
                        lastblock = new byte[P.Length%_sizeBlock];
                        lastoriginaltext = new byte[P.Length % _sizeBlock];
                        for (int j = 0; j < P.Length % _sizeBlock; j++)
                            {
                                lastblock[j] = ctr[NumOfBlocks-1,j];
                                lastoriginaltext[j] = P[_sizeBlock * (NumOfBlocks-1) + j];
                            }
                            lastblock = kz.KuzEncript(lastblock, k);
                            lastblock = AddBymod2(lastoriginaltext, ToBytes(Truncation(To2ich(lastblock),( P.Length % _sizeBlock) * 8)));
                            for (int j = 0; j < P.Length % _sizeBlock; j++)
                            {
                                encrText[(NumOfBlocks - 1) * _sizeBlock + j] = lastblock[j];
                            }
                            return encrText;
                #endregion
                #region Гаммирование с обратной связью по выходу
                case 3:
                    encrText = new byte[V.Length];
                    P = V;
                    if (P.Length % s == 0)
                        NumOfBlocks = P.Length / s;
                    else
                        NumOfBlocks = P.Length / s+1;
                    R = (byte[])IV.Clone();
                    m = IV.Length;  
                        for (int i = 0; i < NumOfBlocks-1; i++)
                        {
                            block = new byte[s];
                            for (int j = 0; j < s; j++)
                            {
                                block[j] = P[i * s + j];
                            }
                            Y = new byte[_sizeBlock];
                            Y = kz.KuzEncript(ToBytes(Truncation(To2ich(R), _sizeBlock*8)), k);
                            block = AddBymod2(block, ToBytes(Truncation(To2ich(Y), s * 8)));
                            byte[] tempR = ToBytes(TruncationBack(To2ich(R), (m-_sizeBlock)*8));
                            for (int h = 0; h < m-_sizeBlock; h++)
                            {
                                R[h] = tempR[h];
                            }
                            for (int h = m - _sizeBlock; h < m; h++)
                            {
                                R[h] = Y[h-m+_sizeBlock];
                            }
                            for (int j = 0; j < s; j++)
                            {
                                encrText[i * s + j] = block[j];
                            }
                        }
                        block = new byte[P.Length%s];
                        for (int j = 0; j < P.Length % s; j++)
                        {
                            block[j] = P[(NumOfBlocks-1) * s + j];
                        }
                            Y = new byte[_sizeBlock];
                            Y = kz.KuzEncript(ToBytes(Truncation(To2ich(R), _sizeBlock*8)), k);
                            block = AddBymod2(block, ToBytes(Truncation(To2ich(Y), (P.Length % s) * 8)));
                            for (int j = 0; j < P.Length % s; j++)
                            {
                                encrText[(NumOfBlocks - 1) * s + j] = block[j];
                            }
                            return encrText;
                #endregion
                #region Простая замена с зацеплением
                case 4:
                    P = ToBytes(Procedure1(To2ich(V), _sizeBlock * 8));
                    encrText = new byte[P.Length];
                    if (P.Length % _sizeBlock == 0)
                        NumOfBlocks = P.Length / _sizeBlock;
                    else
                        NumOfBlocks = P.Length / _sizeBlock + 1;
                    R = (byte[])IV.Clone();
                    m = IV.Length;
                        for (int i = 0; i < NumOfBlocks; i++)
                        {
                            block = new byte[_sizeBlock];
                            
                            originaltext = new byte[_sizeBlock];
                            for (int j = 0; j < _sizeBlock; j++)
                            {
                                originaltext[j] = P[i * _sizeBlock + j];
                            }
                            block = kz.KuzEncript(AddBymod2(originaltext,ToBytes(Truncation(To2ich(R), _sizeBlock*8))), k);
                            byte[] tempR = ToBytes(TruncationBack(To2ich(R), (m-_sizeBlock)*8));
                            for (int h = 0; h < m-_sizeBlock; h++)
                            {
                                R[h] = tempR[h];
                            }
                            for (int h = m - _sizeBlock; h < m; h++)
                            {
                                R[h] = block[h-m+_sizeBlock];
                            }
                            for (int j = 0; j < _sizeBlock; j++)
                            {
                                encrText[i * _sizeBlock + j] = block[j];
                            }
                        }

                            return encrText;
                #endregion
                #region Гаммирование с обратной связью по шифртексту
                case 5:
                    encrText = new byte[V.Length];
                    P = V;
                    if (P.Length % _sizeBlock == 0)
                        NumOfBlocks = P.Length / _sizeBlock;
                    else
                        NumOfBlocks = P.Length / _sizeBlock+1;
                    R = (byte[])IV.Clone();
                    m = IV.Length;
                        for (int i = 0; i < NumOfBlocks-1; i++)
                        {
                            block = new byte[_sizeBlock];
                            originaltext = new byte[_sizeBlock];
                            for (int j = 0; j < _sizeBlock; j++)
                            {
                                originaltext[j] = P[_sizeBlock * i + j];
                                block[j] = P[_sizeBlock * i + j];
                            }
                            block = kz.KuzEncript(ToBytes(Truncation(To2ich(R),_sizeBlock*8)),k);
                            block = AddBymod2(originaltext, ToBytes(Truncation(To2ich(block), s*8)));
                            byte[] tempR = ToBytes(TruncationBack(To2ich(R), (m - s)*8));
                            for (int h = 0; h < m - s; h++)
                            {
                                R[h] = tempR[h];
                            }
                            for (int h = m - s; h < m; h++)
                            {
                                R[h] = block[h - m + s];
                            }
                            for (int j = 0; j < _sizeBlock; j++)
                            {
                                encrText[i * _sizeBlock + j] = block[j];
                            }
                        }
                        block = new byte[P.Length%_sizeBlock];
                        originaltext = new byte[P.Length % _sizeBlock];
                        for (int j = 0; j < P.Length % _sizeBlock; j++)
                            {
                                block[j] = P[_sizeBlock * (NumOfBlocks - 1) + j];
                                originaltext[j] = P[_sizeBlock * (NumOfBlocks-1) + j];
                            }
                            block = kz.KuzEncript(ToBytes(Truncation(To2ich(R), _sizeBlock*8)), k);
                                block = AddBymod2(originaltext, ToBytes(Truncation(To2ich(block), (P.Length % _sizeBlock)*8)));
                                for (int j = 0; j < P.Length % _sizeBlock; j++)
                            {
                                encrText[(NumOfBlocks - 1) * _sizeBlock + j] = block[j];
                            }
                            return encrText;
                #endregion
                #region Выработка имитовставки
                case 6:
                    #region Выработка вспомогательных ключей
                    R = new byte[_sizeBlock];
                    for (int i = 0; i < _sizeBlock; i++)
                    {
                        R[i] = 0;
                    }
                    R = kz.KuzEncript(R, k);
                    K1 = new byte[_sizeBlock];
                    K2 = new byte[_sizeBlock];
                    K1 = Shift(To2ich(R));
                    if (Truncation(To2ich(R),1)[0]!='0')
                    {
                        K1 = AddBymod2(K1, B);
                    }
                    K2 = Shift(To2ich(K1));
                    if (Truncation(To2ich(K1), 1)[0] != '0')
                    {
                        K2 = AddBymod2(K2, B);
                    }
#endregion
                    P = ToBytes(Procedure3(To2ich(V),_sizeBlock*8));
                    byte[] MAC;
                    if (P.Length % _sizeBlock == 0)
                        NumOfBlocks = P.Length / _sizeBlock;
                    else
                        NumOfBlocks = P.Length / _sizeBlock + 1;
                    C = new byte[_sizeBlock];
                    originaltext = new byte[_sizeBlock];
                    for (int i = 0; i < _sizeBlock; i++)
                        C[i] = 0;
                    for (int i = 0; i < NumOfBlocks - 1; i++)
                    {
                        for (int j = 0; j < 16; j++)
                            {
                                originaltext[j] = P[i * _sizeBlock + j];
                            }
                        C = AddBymod2(C, originaltext);
                        C = kz.KuzEncript(C,k);
                    }
                    for (int j = 0; j < P.Length%_sizeBlock; j++)
                    {
                        originaltext[j] = P[(NumOfBlocks - 1) * _sizeBlock + j];
                    }
                    C = AddBymod2(C, originaltext);
                    if (originaltext.Length == _sizeBlock)
                        C = AddBymod2(C, K1);
                    else
                        C = AddBymod2(C, K2);
                    C = kz.KuzEncript(C, k);
                    MAC = ToBytes(Truncation(To2ich(C), s * 8));
                    return MAC;
                #endregion
                default:
                    throw new Exception("Что-то пошло не так");
            }
        }

       
        public byte[] Decrypt() //Расшифрование
        {
            #region Переменные
            byte[] V = File.ReadAllBytes("cipherText.txt");
            byte[] k = File.ReadAllBytes("key.txt");
            int NumOfBlocks;
            byte[] C;
            byte[] block;
            byte[] decrText;
            byte[] decryText;
            byte[] R;
            byte[] Y;
            int m;
            #endregion
            switch (_mode)
            {
                #region Простая замена
                case 1:
                    C = ToBytes(Procedure1(To2ich(V), _sizeBlock * 8));
                    decrText = new byte[C.Length];
                        NumOfBlocks = C.Length / _sizeBlock;
                        for (int i = 0; i < NumOfBlocks; i++)
                        {
                            block = new byte[_sizeBlock];
                            for (int j = 0; j < _sizeBlock; j++)
                            {
                                block[j] = C[i * _sizeBlock + j];
                            }
                            block = kz.KuzDecript(block, k);
                            for (int j = 0; j < _sizeBlock; j++)
                            {
                                decrText[i * _sizeBlock + j] = block[j];
                            }
                        }
                    return decrText;
                #endregion
                #region Гаммирование
                case 2:
                    decrText = new byte[V.Length];
                    C = V;
                    if (C.Length % _sizeBlock == 0)
                        NumOfBlocks = C.Length / _sizeBlock;
                    else
                        NumOfBlocks = C.Length / _sizeBlock+1;
                    byte[,] ctr = CTR(IV, NumOfBlocks);
                        for (int i = 0; i < NumOfBlocks-1; i++)
                        {
                            block = new byte[_sizeBlock];
                            byte[] decrytext = new byte[_sizeBlock];
                            for (int j = 0; j < _sizeBlock; j++)
                            {
                                block[j] = ctr[i,j];
                                decrytext[j] = C[_sizeBlock * i + j];
                            }
                            block = kz.KuzEncript(block, k);
                            block = AddBymod2(decrytext, ToBytes(Truncation(To2ich(block), s*8)));
                            for (int j = 0; j < _sizeBlock; j++)
                            {
                                decrText[i * _sizeBlock + j] = block[j];
                            }
                        }
                        byte[] lastblock = new byte[C.Length%_sizeBlock];
                        byte[] lastdecrytext = new byte[C.Length % _sizeBlock];
                        for (int j = 0; j < C.Length % _sizeBlock; j++)
                            {
                                lastblock[j] = ctr[NumOfBlocks-1,j];
                                lastdecrytext[j] = C[_sizeBlock * (NumOfBlocks - 1) + j];
                            }
                            lastblock = kz.KuzEncript(lastblock, k);
                            lastblock = AddBymod2(lastdecrytext, ToBytes(Truncation(To2ich(lastblock), (C.Length % _sizeBlock) * 8)));
                            for (int j = 0; j < C.Length % _sizeBlock; j++)
                            {
                                decrText[(NumOfBlocks - 1) * _sizeBlock + j] = lastblock[j];
                            }
                            return decrText;
                #endregion
                #region Гаммирование с обратной связью по выходу
                case 3:
                    decrText = new byte[V.Length];
                    C = V;
                    if (C.Length % s == 0)
                        NumOfBlocks = C.Length / s;
                    else
                        NumOfBlocks = C.Length / s+1;
                    R = (byte[])IV.Clone();
                    m = IV.Length;
                        for (int i = 0; i < NumOfBlocks-1; i++)
                        {
                            block = new byte[s];
                            for (int j = 0; j < s; j++)
                            {
                                block[j] = C[i * s + j];
                            }
                            Y = new byte[_sizeBlock];
                            Y = kz.KuzEncript(ToBytes(Truncation(To2ich(R), _sizeBlock*8)), k);
                            block = AddBymod2(block, ToBytes(Truncation(To2ich(Y), s * 8)));
                            byte[] tempR = ToBytes(TruncationBack(To2ich(R),( m-_sizeBlock)*8));
                            for (int h = 0; h < m-_sizeBlock; h++)
                            {
                                R[h] = tempR[h];
                            }
                            for (int h = m - _sizeBlock; h < m; h++)
                            {
                                R[h] = Y[h-m+_sizeBlock];
                            }
                            for (int j = 0; j < s; j++)
                            {
                                decrText[i * s + j] = block[j];
                            }
                        }
                        block = new byte[C.Length % s];
                        for (int j = 0; j < C.Length % s; j++)
                        {
                            block[j] = C[(NumOfBlocks-1) * s + j];
                        }
                            Y = new byte[_sizeBlock];
                            Y = kz.KuzEncript(ToBytes(Truncation(To2ich(R), _sizeBlock*8)), k);
                            block = AddBymod2(block, ToBytes(Truncation(To2ich(Y), (C.Length % s) * 8)));
                            for (int j = 0; j < C.Length % s; j++)
                            {
                                decrText[(NumOfBlocks - 1) * s + j] = block[j];
                            }
                            return decrText;
                #endregion
                #region Простая замена с зацеплением
                case 4:
                    C = ToBytes(Procedure1(To2ich(V), _sizeBlock * 8));
                    decrText = new byte[C.Length];
                    if (C.Length % _sizeBlock == 0)
                        NumOfBlocks = C.Length / _sizeBlock;
                    else
                        NumOfBlocks = C.Length / _sizeBlock + 1;
                    R = (byte[])IV.Clone();
                    m = IV.Length;
                        for (int i = 0; i < NumOfBlocks; i++)
                        {
                            block = new byte[_sizeBlock];
                            decryText = new byte[_sizeBlock];
                            for (int j = 0; j < _sizeBlock; j++)
                            {
                                decryText[j] = C[i * _sizeBlock + j];
                            }
                            block = kz.KuzDecript(decryText, k);
                            block = AddBymod2(block, ToBytes(Truncation(To2ich(R),_sizeBlock*8)));
                            byte[] tempR = ToBytes(TruncationBack(To2ich(R), (m-_sizeBlock)*8));
                            for (int h = 0; h < m-_sizeBlock; h++)
                            {
                                R[h] = tempR[h];
                            }
                            for (int h = m - _sizeBlock; h < m; h++)
                            {
                                R[h] = decryText[h - m + _sizeBlock];
                            }
                            for (int j = 0; j < _sizeBlock; j++)
                            {
                                decrText[i * _sizeBlock + j] = block[j];
                            }
                        }

                            return decrText;
                #endregion
                #region Гаммирование с обратной связью по шифртексту
                case 5:
                    decrText = new byte[V.Length];
                    C = V;
                    if (C.Length % _sizeBlock == 0)
                        NumOfBlocks = C.Length / _sizeBlock;
                    else
                        NumOfBlocks = C.Length / _sizeBlock+1;
                    R = (byte[])IV.Clone();
                    m = IV.Length;
                        for (int i = 0; i < NumOfBlocks-1; i++)
                        {
                            block = new byte[_sizeBlock];
                            decryText = new byte[_sizeBlock];
                            for (int j = 0; j < _sizeBlock; j++)
                            {
                                block[j] = C[_sizeBlock * i + j];
                                decryText[j] = C[_sizeBlock * i + j];
                            }
                            block = kz.KuzEncript(ToBytes(Truncation(To2ich(R),_sizeBlock*8)),k);
                            block = AddBymod2(decryText, ToBytes(Truncation(To2ich(block), s*8)));
                            byte[] tempR = ToBytes(TruncationBack(To2ich(R), (m - s)*8));
                            for (int h = 0; h < m - s; h++)
                            {
                                R[h] = tempR[h];
                            }
                            for (int h = m - s; h < m; h++)
                            {
                                R[h] = decryText[h - m + s];
                            }
                            for (int j = 0; j < _sizeBlock; j++)
                            {
                                decrText[i * _sizeBlock + j] = block[j];
                            }
                        }
                        block = new byte[C.Length%_sizeBlock];
                        decryText = new byte[C.Length % _sizeBlock];
                        for (int j = 0; j < C.Length % _sizeBlock; j++)
                            {
                                block[j] = C[_sizeBlock * (NumOfBlocks - 1) + j];
                                decryText[j] = C[_sizeBlock * (NumOfBlocks - 1) + j];
                            }
                            block = kz.KuzEncript(ToBytes(Truncation(To2ich(R), _sizeBlock*8)), k);
                            block = AddBymod2(decryText, ToBytes(Truncation(To2ich(block), (C.Length % _sizeBlock)*8)));
                                for (int j = 0; j < C.Length % _sizeBlock; j++)
                            {
                                decrText[(NumOfBlocks - 1) * _sizeBlock + j] = block[j];
                            }
                                return decrText;
                #endregion
                #region Выработка имитовставки
                case 6:
                    throw new Exception("У имитовставки нет расшифровки");
                #endregion
                default:
                    throw new Exception("Что-то пошло не так");
            }
        }
        #region CTR; XOR; Байты в двоичное представление; Двоичное представление в байты; Сдвиг битов
        private byte[,] CTR(byte[] _IV,int NumBlock)
        {
            byte[,] _ctr = new byte[NumBlock,_sizeBlock];
            for (int i = 0; i < _sizeBlock/2; i++)
            {
                _ctr[0, i] = _IV[i];
            }
            for (int i = _sizeBlock / 2; i < _sizeBlock; i++)
            {
                _ctr[0, i] = 0;
            }
            for (int i = 1; i < NumBlock; i++)
            {
                for (int j = 0; j < _sizeBlock; j++)
                {
                        _ctr[i, j]=_ctr[i-1,j];
                }
                for (int j = _sizeBlock-1; j >-1; j--)
                {
                    if (_ctr[i - 1, j] + 1 != 127)
                    {
                        _ctr[i, j]++;
                        break;
                    }
                    else
                    {
                        _ctr[i, j] = 0;
                    }
                }
            }
            return _ctr;
        }
        private byte[] AddBymod2(byte[] input1, byte[] input2) // Преобразование Х (сложение 2х веторов по модулю 2)
        {
            byte[] output = new byte[(input1.Length>input2.Length)?input1.Length:input2.Length];
            output = (input1.Length > input2.Length) ? input1 : input2;
            for (int i = 0; i < ((input1.Length > input2.Length) ? input2.Length : input1.Length); i++)
            {
                string in1 = Convert.ToString(input1[i], 2).PadLeft(8, '0');
                string in2 = Convert.ToString(input2[i], 2).PadLeft(8, '0');
                string temp = "";
                for (int j = 0; j < 8; j++)
                {
                    temp+= (int.Parse(in1[j].ToString()) + int.Parse(in2[j].ToString()) % 2 == 1) ?'1' : '0';
                }
                output[i] = Convert.ToByte(temp, 2);
            }
            return output;
        }
        private string To2ich(byte[] input)
        {
            string output = "";
            for (int i = 0; i < input.Length; i++)
            {
                output+=Convert.ToString(input[i], 2).PadLeft(8, '0');
            }
            return output;
        }
        private byte[] ToBytes(string input)
        {
            int numOfBytes = input.Length / 8;
            byte[] output = new byte[numOfBytes];
            for (int i = 0; i < numOfBytes; i++)
            {
                output[i] = Convert.ToByte(input.Substring(8 * i, 8), 2);
            }
            return output;
        }
        private byte[] Shift(string input)
        {
            string temp = input.Substring(1, input.Length - 1) + '0';
            return ToBytes(temp);
        }
        #endregion
    }
}
