import { FC } from 'react';
import logoIcon from '../../Icons/png/system-settings-icon.png';
import './Header.css';

export const Header : FC = () => {
    return (
        <div className="header--container">
            <div className="header-logo--container">
                <div className="header-logo--image">
                    <img src={logoIcon} alt="" />
                </div>
                <div className="header-logo--text">
                    <span> PCAP Analyzer </span>
                </div>
            </div>
            <div className="header-body--container">
                <div className="body--upload-button">
                    <button>Загрузить .pcapng файл</button>
                </div>
            </div>
        </div>

    )
}