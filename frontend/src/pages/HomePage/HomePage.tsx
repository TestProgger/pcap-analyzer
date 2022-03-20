import { observer } from "mobx-react-lite";
import { FC } from "react";
import { Header } from "../../components/Header/Header";

const HomePage : FC = () => {
    return(
        <div className="home-page--container">
            <div className="home-page--table--container">
                <table>
                    <thead>
                        <tr>
                            <th> № потока </th>
                            <th> Дата и время потока </th>
                            <th>  </th>    
                        </tr>    
                    </thead>    
                </table>    
            </div>
        </div>
    )
}

export default observer(HomePage)