/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of CSMS <https://github.com/OpenChargingCloud/CSMS>
 *
 * Licensed under the Affero GPL license, Version 3.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.gnu.org/licenses/agpl.html
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// The system's time, and timers that never fire.
    /// </summary>
    /// <remarks>
    /// For a CSMS started with NTS switched on, which schedules a check of its
    /// clock a minute in. A test has no business asking the PTB the time, and
    /// nothing tested through this clock waits for a timer - what is asked is
    /// what the CSMS says when it sets one.
    /// </remarks>
    internal sealed class TimerlessClock : TimeProvider
    {

        public override ITimer CreateTimer(TimerCallback  Callback,
                                           Object?        State,
                                           TimeSpan       DueTime,
                                           TimeSpan       Period)

            => new NeverFires();

        private sealed class NeverFires : ITimer
        {
            public Boolean   Change(TimeSpan DueTime, TimeSpan Period) => true;
            public void      Dispose() { }
            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        }

    }

}
